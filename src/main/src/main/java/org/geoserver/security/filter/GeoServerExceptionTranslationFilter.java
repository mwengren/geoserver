/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.geoserver.security.config.ExceptionTranslationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.util.StringUtils;

/**
 * Named Exception translation filter
 * 
 * The {@link AuthenticationEntryPoint} is determined in the following order
 * 
 * if {@link ExceptionTranslationFilterConfig#getAuthenticationEntryPointName()} is not empty,
 * use a lookup in the Spring context.
 * 
 * if the name is empty, use {@link GeoServerSecurityFilter#AUTHENTICATION_ENTRY_POINT_HEADER}
 * as a servlet attribute name. Previous authentication filter should put an entry point in 
 * this attribute.
 * 
 * if still no entry point was a found, use {@link Http403ForbiddenEntryPoint} as a default.
 * 
 * 
 * @author mcr
 *
 */
public class GeoServerExceptionTranslationFilter extends GeoServerCompositeFilter {
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        
        ExceptionTranslationFilterConfig authConfig = 
                (ExceptionTranslationFilterConfig) config;
        
        
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter() {

            @Override
            public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                    throws IOException, ServletException {
                
                // check for  entry point and remove it in any case
                AuthenticationEntryPoint aep = (AuthenticationEntryPoint) req.getAttribute(GeoServerSecurityFilter.AUTHENTICATION_ENTRY_POINT_HEADER);
                if (aep!=null)
                    req.removeAttribute(AUTHENTICATION_ENTRY_POINT_HEADER);
                
                // if the entry point is null, set it
                ExceptionTranslationFilter filter = (ExceptionTranslationFilter)getNestedFilters().get(0);
                if (filter.getAuthenticationEntryPoint()== null) {
                    if (aep==null)
                        aep=new Http403ForbiddenEntryPoint();
                    filter.setAuthenticationEntryPoint(aep);
                }
                super.doFilter(req, res, chain);
            }
            
        };
        
        if (StringUtils.hasLength(authConfig.getAuthenticationFilterName())) {
            GeoServerSecurityFilter authFilter = getSecurityManager().loadFilter(authConfig.getAuthenticationFilterName());
            filter.setAuthenticationEntryPoint(authFilter.getAuthenticationEntryPoint());
        }
                        
        if (StringUtils.hasLength(authConfig.getAccessDeniedErrorPage())) {
            AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
            accessDeniedHandler.setErrorPage(authConfig.getAccessDeniedErrorPage());
            filter.setAccessDeniedHandler(accessDeniedHandler);
        }
        
        // does not work since the authentication entry point can be set dynamically
        //filter.afterPropertiesSet();
        getNestedFilters().add(filter);        
    }
    
}
