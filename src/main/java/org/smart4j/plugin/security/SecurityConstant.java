package org.smart4j.plugin.security;

/**
 * 常量接口
 * Created by yuezhang on 17/11/6.
 */
public interface SecurityConstant {

    String REALMS = "smart.plugin.security.realms";

    String REALMS_JDBC = "jdbc";

    String REALMS_CUSTOM = "custom";

    String SMART_SECURITY = "smart.plugin.security.custom.class";

    String JDBC_AUTHC_QUERY = "smart.plugin.security.jdbc.authc_query";

}