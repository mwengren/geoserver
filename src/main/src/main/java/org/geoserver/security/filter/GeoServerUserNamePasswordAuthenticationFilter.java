/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */
package org.geoserver.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.config.UsernamePasswordAuthenticationFilterConfig;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

/**
 * User name / password authentication filter
 * 
 * 
 * @author christian
 * 
 */
public class GeoServerUserNamePasswordAuthenticationFilter extends GeoServerCompositeFilter {

    public static final String URL_AFTER_LOGOUT="/web/";
    public static final String URL_FOR_LOGIN = "/j_spring_security_check";
    public static final String URL_FOR_LOGOUT= "/j_spring_security_logout";
    public static final String URL_LOGIN_SUCCCESS = "/";
    public static final String URL_LOGIN_FAILURE = "/web/?wicket:bookmarkablePage=:org.geoserver.web.GeoServerLoginPage&amp;error=true";
    public static final String URL_LOGIN_FORM="/admin/login.do";
    
    private LoginUrlAuthenticationEntryPoint aep;  

    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        
        UsernamePasswordAuthenticationFilterConfig upConfig = (UsernamePasswordAuthenticationFilterConfig) config;
        
        aep=new LoginUrlAuthenticationEntryPoint();
        aep.setLoginFormUrl(URL_LOGIN_FORM);
        aep.setForceHttps(false);
        try {
            aep.afterPropertiesSet();
        } catch (Exception e2) {
            throw new IOException(e2);
        }

        // TODO, Justin, is this correct
        RememberMeServices rms = (RememberMeServices) GeoServerExtensions
                .bean("rememberMeServices");

        // add logout filter
        LogoutFilter logoutFilter = new LogoutFilter(URL_AFTER_LOGOUT, (LogoutHandler) rms,
                new SecurityContextLogoutHandler());
        logoutFilter.setFilterProcessesUrl(URL_FOR_LOGOUT);
        
        try {
            logoutFilter.afterPropertiesSet();
        } catch (ServletException e1) {
            throw new IOException(e1);
        }
        getNestedFilters().add(logoutFilter);

        // add login filter
        UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter(){

            @Override
            public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                    throws IOException, ServletException {
                req.setAttribute(GeoServerSecurityFilter.AUTHENTICATION_ENTRY_POINT_HEADER, aep);
                super.doFilter(req, res, chain);
            }            
        };
;

        filter.setPasswordParameter(upConfig.getPasswordParameterName());
        filter.setUsernameParameter(upConfig.getUsernameParameterName());
        filter.setAuthenticationManager(getSecurityManager());

        filter.setRememberMeServices(rms);
        WebAuthenticationDetailsSource s = new WebAuthenticationDetailsSource();
        s.setClazz(GeoServerWebAuthenticationDetails.class);
        filter.setAuthenticationDetailsSource(s);

        filter.setAllowSessionCreation(false);
        filter.setFilterProcessesUrl(URL_FOR_LOGIN);

        SimpleUrlAuthenticationSuccessHandler successHandler = new SimpleUrlAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl(URL_LOGIN_SUCCCESS);
        filter.setAuthenticationSuccessHandler(successHandler);

        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
        // TODO, check this when using encrypting of URL parameters
        failureHandler
                .setDefaultFailureUrl(URL_LOGIN_FAILURE);
        filter.setAuthenticationFailureHandler(failureHandler);

        filter.afterPropertiesSet();
        getNestedFilters().add(filter);

        // TODO, is this necessary
        SecurityContextHolderAwareRequestFilter contextAwareFilter = new SecurityContextHolderAwareRequestFilter();
        try {
            contextAwareFilter.afterPropertiesSet();
        } catch (ServletException e) {
            throw new IOException(e);
        }
        getNestedFilters().add(contextAwareFilter);
    }
}
