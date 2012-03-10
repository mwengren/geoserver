/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.config.BasicAuthenticationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Named Basic Authentication Filter
 * 
 * @author mcr
 *
 */
public class GeoServerBasicAuthenticationFilter extends GeoServerCompositeFilter {
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        
        BasicAuthenticationFilterConfig authConfig = 
                (BasicAuthenticationFilterConfig) config;
        
        BasicAuthenticationFilter filter = new BasicAuthenticationFilter();
        filter.setAuthenticationManager(getSecurityManager());
        filter.setIgnoreFailure(false);
        // TODO, Justin, is this correct
        AuthenticationEntryPoint ep = (AuthenticationEntryPoint) 
                GeoServerExtensions.bean("basicProcessingFilterEntryPoint");
        filter.setAuthenticationEntryPoint(ep);

        // TODO, Justin, is this correct
        if (authConfig.isUseRememberMe()) {             
            filter.setRememberMeServices((RememberMeServices)
                    GeoServerExtensions.bean("rememberMeServices"));
            WebAuthenticationDetailsSource s = new WebAuthenticationDetailsSource();
            s.setClazz(GeoServerWebAuthenticationDetails.class);
            filter.setAuthenticationDetailsSource(s);
        }
        filter.afterPropertiesSet();
        getNestedFilters().add(filter);        
    }
    
}
