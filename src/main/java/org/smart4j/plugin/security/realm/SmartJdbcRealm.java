package org.smart4j.plugin.security.realm;

import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.smart4j.framework.helper.DatabaseHelper;
import org.smart4j.plugin.security.passpord.Md5CredentialsMatcher;

/**
 * 基于Smart的JDBC Realm（需要提供相关smart.plugin.security.jdbc.* 配置项）
 * Created by yuezhang on 17/11/5.
 */
public class SmartJdbcRealm extends JdbcRealm {

    public SmartJdbcRealm(){
        super.setDataSource(DatabaseHelper.getDataSource());
        super.setAuthenticationQuery(SecurityConfig.getJdbcAuthcQuery());
        super.setUserRolesQuery(SecurityConfig.getJdbcRolesQuery());
        super.setPermissionsQuery(SecurityConfig.getJdbcPermissionsQuery());
        super.setPermissionsLookupEnabled(true); // 开启后可连接permission表进行查询
        super.setCredentialsMatcher(new Md5CredentialsMatcher()); // 基于MD5的密码匹配机制
    }

}
