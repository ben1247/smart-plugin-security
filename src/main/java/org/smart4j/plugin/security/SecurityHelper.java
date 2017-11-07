package org.smart4j.plugin.security;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *  Security 助手类
 * Created by Administrator on 2017\11\7 0007.
 */
public final class SecurityHelper {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityHelper.class);

    /**
     * 登录
     * @param username
     * @param password
     */
    public static void login(String username , String password){
        Subject currentUser = SecurityUtils.getSubject();
        if(currentUser != null){
            UsernamePasswordToken token = new UsernamePasswordToken(username,password);
            try {
                currentUser.login(token);
            }catch (AuthenticationException e){
                LOGGER.error("login failure",e);
                throw new AuthcException(e);
            }
        }
    }

    public static void logout(){
        Subject currentUser = SecurityUtils.getSubject();
        if(currentUser != null){
            currentUser.logout();
        }
    }

}
