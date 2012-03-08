/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;
import java.nio.charset.Charset;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.HttpDigestUserDetailsServiceWrapper;
import org.geoserver.security.config.DigestAuthenticationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

/**
 * Named Digest Authentication Filter
 * 
 * @author mcr
 *
 */
public class GeoServerDigestAuthenticationFilter extends GeoServerCompositeFilter {
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        
        DigestAuthenticationFilterConfig authConfig = 
                (DigestAuthenticationFilterConfig) config;
        
        DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
        filter.setCreateAuthenticatedToken(true);
        filter.setPasswordAlreadyEncoded(true);
        // TODO, Justin, is this correct
        DigestAuthenticationEntryPoint ep = (DigestAuthenticationEntryPoint) 
                GeoServerExtensions.bean("digestProcessingFilterEntryPoint");
        
        filter.setAuthenticationEntryPoint(ep);
        
        
        HttpDigestUserDetailsServiceWrapper wrapper = 
                new HttpDigestUserDetailsServiceWrapper(
                        getSecurityManager().loadUserGroupService(authConfig.getUserGroupServiceName()),
                        Charset.defaultCharset()); 
        filter.setUserDetailsService(wrapper);
        
        filter.afterPropertiesSet();
        getNestedFilters().add(filter);        
    }
    
}
