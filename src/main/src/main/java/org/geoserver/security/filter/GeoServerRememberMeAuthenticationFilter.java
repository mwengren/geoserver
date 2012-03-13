/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;

/**
 * Named RemeberMe Authentication Filter
 * 
 * @author mcr
 *
 */
public class GeoServerRememberMeAuthenticationFilter extends GeoServerCompositeFilter {
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        
//       not needed at the moment        
//        RememberMeAuthenticationFilterConfig authConfig = 
//                (RememberMeAuthenticationFilterConfig) config;
        
        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        filter.setAuthenticationManager(getSecurityManager());

        // TODO, Justin, is this correct
        filter.setRememberMeServices((RememberMeServices)
                   GeoServerExtensions.bean("rememberMeServices"));
        filter.afterPropertiesSet();
        getNestedFilters().add(filter);        
    }
    
}
