package com.lh.framework.web.service;

import javax.annotation.Resource;

import com.lh.baseconfig.domain.UserInfo;
import com.lh.baseconfig.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import com.lh.common.constant.Constants;
import com.lh.common.core.domain.entity.SysUser;
import com.lh.common.core.domain.model.LoginUser;
import com.lh.common.core.redis.RedisCache;
import com.lh.common.exception.CustomException;
import com.lh.common.exception.user.CaptchaException;
import com.lh.common.exception.user.CaptchaExpireException;
import com.lh.common.exception.user.UserPasswordNotMatchException;
import com.lh.common.utils.DateUtils;
import com.lh.common.utils.MessageUtils;
import com.lh.common.utils.ServletUtils;
import com.lh.common.utils.ip.IpUtils;
import com.lh.framework.manager.AsyncManager;
import com.lh.framework.manager.factory.AsyncFactory;
import com.lh.system.service.ISysConfigService;
import com.lh.system.service.ISysUserService;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * 登录校验方法
 *
 * @author lh
 */
@Component
public class SysLoginService
{
    @Autowired
    private TokenService tokenService;

    @Resource
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Autowired
    private ISysUserService userService;

    @Autowired
    private ISysConfigService configService;

    @Autowired
    private UserInfoService userInfoService;

    /**
     * 登录验证
     *
     * @param username 用户名
     * @param password 密码
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */
    public String login(String username, String password, String code, String uuid)
    {
        boolean captchaOnOff = configService.selectCaptchaOnOff();
        // 验证码开关
        if (captchaOnOff)
        {
            validateCaptcha(username, code, uuid);
        }
        // 用户验证
        Authentication authentication = null;
        try
        {
            // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(username, password));
        }
        catch (Exception e)
        {
            if (e instanceof BadCredentialsException)
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
                throw new UserPasswordNotMatchException();
            }
            else
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, e.getMessage()));
                throw new CustomException(e.getMessage());
            }
        }
        AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        recordLoginInfo(loginUser.getUser());
        // 生成token
        return tokenService.createToken(loginUser);
    }

    /**
     * 校验验证码
     *
     * @param username 用户名
     * @param code 验证码
     * @param uuid 唯一标识
     * @return 结果
     */
    public void validateCaptcha(String username, String code, String uuid)
    {
        String verifyKey = Constants.CAPTCHA_CODE_KEY + uuid;
        String captcha = redisCache.getCacheObject(verifyKey);
        redisCache.deleteObject(verifyKey);
        if (captcha == null)
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.jcaptcha.expire")));
            throw new CaptchaExpireException();
        }
        if (!code.equalsIgnoreCase(captcha))
        {
            AsyncManager.me().execute(AsyncFactory.recordLogininfor(username, Constants.LOGIN_FAIL, MessageUtils.message("user.jcaptcha.error")));
            throw new CaptchaException();
        }
    }

    /**
     * 记录登录信息
     */
    public void recordLoginInfo(SysUser user)
    {
        user.setLoginIp(IpUtils.getIpAddr(ServletUtils.getRequest()));
        user.setLoginDate(DateUtils.getNowDate());
        userService.updateUserProfile(user);
    }

    public Map<String,Object> loginWeiXin(String openId,String sessionKey)
    {
        Map<String,Object> map=new HashMap();
        // 用户验证
        Authentication authentication = null;
        try
        {
            UserInfo userInfo = userInfoService.getUserInfoByOpenId(openId);
            if(userInfo!=null){
                userInfo.setSessionKey(sessionKey);
                userInfoService.updateUserInfo(userInfo);
            }else{
                //新增用户数UserDetailsServiceImpl据
                UserInfo newUserInfo = new UserInfo();
                newUserInfo.setOpenId(openId);
                newUserInfo.setUserType("1");
                newUserInfo.setCreateTime(new Date());
                newUserInfo.setSessionKey(sessionKey);
                int result = userInfoService.addUserInfo(newUserInfo);
            }

            // 该方法会去调用UserDetailsServiceImpl.loadUserByUsername
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(openId, "admin123"));
        }
        catch (Exception e)
        {
            if (e instanceof BadCredentialsException)
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(openId, Constants.LOGIN_FAIL, MessageUtils.message("user.password.not.match")));
                throw new UserPasswordNotMatchException();
            }
            else
            {
                AsyncManager.me().execute(AsyncFactory.recordLogininfor(openId, Constants.LOGIN_FAIL, e.getMessage()));
                throw new CustomException(e.getMessage());
            }
        }
        AsyncManager.me().execute(AsyncFactory.recordLogininfor(openId, Constants.LOGIN_SUCCESS, MessageUtils.message("user.login.success")));
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        //recordLoginInfo(loginUser.getUser());
        // 生成token
        String token= tokenService.createToken(loginUser);
        map.put(Constants.TOKEN, token);
        map.put("userinfo",loginUser);
        return map;
    }

}
