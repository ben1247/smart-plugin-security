package org.smart4j.plugin.security.passpord;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.smart4j.framework.util.CodecUtil;

/**
 * MD5 密码匹配器
 * Created by yuezhang on 17/11/5.
 */
public class Md5CredentialsMatcher implements CredentialsMatcher {

    /**
     * 只需实现Shiro提供的CredentialsMatcher接口即可完成该接口提供doCredentialsMatch方法。
     * @param token 可通过该参数获取从表单提交过来的密码，该密码是明文，尚未通过MD5加密。
     * @param info  可通过该参数获取数据库中存储的密码，该密码已通过MD5加密。
     * @return
     */
    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        // 获取从表单提交过来的密码、明文、尚未通过MD5加密
        String submitted = String.valueOf(((UsernamePasswordToken)token).getPassword());
        // 获取数据库中存储的密码，已通过MD5加密
        String encrypted = String.valueOf(info.getCredentials());
        return CodecUtil.md5(submitted).equals(encrypted);
    }
}
