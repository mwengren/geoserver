/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.config.ExceptionTranslationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.ExceptionTranslationFilter;

/**
 * Named Exception translation filter
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
        
        
        ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
        
        // TODO, Justin, is this correct
        AuthenticationEntryPoint ep = (AuthenticationEntryPoint) 
                GeoServerExtensions.bean(authConfig.getAuthenticationEntryPointName());
                
        filter.setAuthenticationEntryPoint(ep);
        if (authConfig.getAccessDeniedErrorPage()!=null && authConfig.getAccessDeniedErrorPage().length()>0) {
            AccessDeniedHandlerImpl accessDeniedHandler = new AccessDeniedHandlerImpl();
            accessDeniedHandler.setErrorPage(authConfig.getAccessDeniedErrorPage());
            filter.setAccessDeniedHandler(accessDeniedHandler);
        }
        
        filter.afterPropertiesSet();
        getNestedFilters().add(filter);        
    }
    
}
