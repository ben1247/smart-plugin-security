package org.smart4j.plugin.security;

import org.apache.shiro.web.env.EnvironmentLoaderListener;

import javax.servlet.FilterRegistration;
import javax.servlet.ServletContainerInitializer;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import java.util.Set;

/**
 * Smart Security 插件
 * 通过Shiro提供的初始化参数来定制默认的Shiro配置文件名，通过ServletContext注册Listener与Filter，
 * 只是这里注册的不是ShiroFilter，而是SmartSecurityFilter，它是前者的扩展。
 * Created by yuezhang on 17/11/2.
 */
public class SmartSecurityPlugin implements ServletContainerInitializer{

    @Override
    public void onStartup(Set<Class<?>> c, ServletContext ctx) throws ServletException {
        // 设置初始化参数
        ctx.setInitParameter("shiroConfigLocations","classpath:smart-security.ini");
        // 注册Listener
        ctx.addListener(EnvironmentLoaderListener.class);
        // 注册Filter
        FilterRegistration.Dynamic smartSecurityFilter = ctx.addFilter("SmartSecurityFilter",SmartSecurityFilter.class);
        smartSecurityFilter.addMappingForUrlPatterns(null,false,"/*");
    }
}
