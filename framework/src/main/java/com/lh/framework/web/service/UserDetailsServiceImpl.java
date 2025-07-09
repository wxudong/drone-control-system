package com.lh.framework.web.service;

import com.lh.baseconfig.domain.Permission;
import com.lh.baseconfig.domain.UserInfo;
import com.lh.baseconfig.service.PostPermissionService;
import com.lh.baseconfig.service.UserInfoService;
import com.lh.common.core.domain.entity.SysRole;
import com.lh.system.mapper.SysUserPostMapper;
import com.lh.system.service.ISysPostService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import com.lh.common.core.domain.entity.SysUser;
import com.lh.common.core.domain.model.LoginUser;
import com.lh.common.enums.UserStatus;
import com.lh.common.exception.BaseException;
import com.lh.common.utils.StringUtils;
import com.lh.system.service.ISysUserService;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * 用户验证处理
 *
 * @author lh
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService
{
    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Autowired
    private ISysUserService userService;

    @Autowired
    private SysPermissionService permissionService;

    @Autowired
    private UserInfoService userInfoService;

    @Autowired
    private ISysPostService sysPostService;

    @Autowired
    private PostPermissionService postPermissionService;

    @Autowired
    private SysUserPostMapper sysUserPostMapper;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        SysUser user = userService.selectUserByUserName(username);
        //判断当前用户有没有权限登录后台
        if(user!=null){
            Long postId = sysPostService.getPostIdByUserId(user.getUserId());
            //查询当前职务有没有
            List<Permission> permissionList= postPermissionService.getPermissionListByPostId(postId);
            if(permissionList.stream().filter(permission -> permission.getEnglishName().equals("login")).findAny().isPresent()){

            }else if(username.equals("admin")){

            }
            else{
                log.info("登录用户：{} 已被停用.", username);
                throw new BaseException("对不起，您的账号：" + username + " 已被停用");
            }
        }
        if (StringUtils.isNull(user))
        {
            user=new SysUser();
            UserInfo userInfo=userInfoService.getUserInfoByOpenId(username);
            if(userInfo!=null){
                String phone = userInfo.getPhone();
                if(null!=phone&&!"".equals(phone)){
                    SysUser sysUser = userService.selectSysUserByPhone(phone);
                    if(sysUser!=null) {
                        Long userId = sysUser.getUserId();
                        List<Integer> postIdList = sysPostService.selectPostListByUserId(userId);
                        if (!CollectionUtils.isEmpty(postIdList)) {
                            int postId = postIdList.get(0);
                            //查询岗位对应的权限
                            List<Permission> permissionList = postPermissionService.getPermissionListByPostId(Long.valueOf(postId));
                            List<SysRole> roles = new ArrayList<SysRole>();
                            permissionList.stream().forEach(permission -> {
                                SysRole sysRole = new SysRole();
                                sysRole.setRoleName(permission.getEnglishName());
                                sysRole.setRoleId(permission.getId());
                                roles.add(sysRole);
                            });
                            user.setRoles(roles);
                        }
                    }

                }
                user.setUserId(userInfo.getId());
                user.setAvatar(userInfo.getAvatar());
                user.setUserName(userInfo.getNickName());
                user.setPhonenumber(userInfo.getPhone());
                user.setUserType(userInfo.getUserType());
               // user.setUserName(username);
                user.setPassword("$2a$10$7JB720yubVSZvUI0rEqK/.VqGOZTH.ulu33dHOiBE8ByOhJIrdAu2");
            }else{
                log.info("登录用户：{} 不存在.", username);
                throw new UsernameNotFoundException("登录用户：" + username + " 不存在");
            }
        }
        else if (UserStatus.DELETED.getCode().equals(user.getDelFlag()))
        {
            log.info("登录用户：{} 已被删除.", username);
            throw new BaseException("对不起，您的账号：" + username + " 已被删除");
        }
        else if (UserStatus.DISABLE.getCode().equals(user.getStatus()))
        {
            log.info("登录用户：{} 已被停用.", username);
            throw new BaseException("对不起，您的账号：" + username + " 已停用");
        }

        return createLoginUser(user);
    }

    public UserDetails createLoginUser(SysUser user)
    {
        return new LoginUser(user.getUserId(),user.getDeptId(),user, permissionService.getMenuPermission(user));
    }
}
