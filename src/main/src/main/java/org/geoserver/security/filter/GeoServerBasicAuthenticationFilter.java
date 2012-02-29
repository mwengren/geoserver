/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.BasicAuthenticationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Named Basice Authentication Filter
 * 
 * @author mcr
 *
 */
public class GeoServerBasicAuthenticationFilter extends GeoServerComplexFilter {
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        
        BasicAuthenticationFilterConfig authConfig = 
                (BasicAuthenticationFilterConfig) config;
        
        BasicAuthenticationFilter filter = new BasicAuthenticationFilter();
        filter.setAuthenticationManager(getSecurityManager());
        filter.setIgnoreFailure(authConfig.isIgnoreFailure());
        if (authConfig.isIgnoreFailure()==false) {
            BasicAuthenticationEntryPoint ep = new BasicAuthenticationEntryPoint();
            ep.setRealmName(GeoServerSecurityManager.REALM);
            filter.setAuthenticationEntryPoint(ep);
        }
        String rememberMeServiceName = authConfig.getRememberMeServiceName();
        if (rememberMeServiceName !=null && rememberMeServiceName.length() >0) {
            // TODO, this is not correct
            filter.setRememberMeServices((RememberMeServices)
                    GeoServerExtensions.bean(rememberMeServiceName));
        }
        filter.afterPropertiesSet();
        getNestedFilters().add(filter);        
    }
    
}
