/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;
import java.nio.charset.Charset;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.HttpDigestUserDetailsServiceWrapper;
import org.geoserver.security.config.DigestAuthenticationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

/**
 * Named Digest Authentication Filter
 * 
 * @author mcr
 *
 */
public class GeoServerDigestAuthenticationFilter extends GeoServerCompositeFilter {
    
    private DigestAuthenticationEntryPoint aep;
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);


        
        DigestAuthenticationFilterConfig authConfig = 
                (DigestAuthenticationFilterConfig) config;

        aep = new DigestAuthenticationEntryPoint();
        aep.setKey(config.getName());
        aep.setNonceValiditySeconds(
                authConfig.getNonceValiditySeconds()<=0 ? 300 : authConfig.getNonceValiditySeconds());
        aep.setRealmName(GeoServerSecurityManager.REALM);
        try {
            aep.afterPropertiesSet();
        } catch (Exception e) {
            throw new IOException(e);
        }
        
        DigestAuthenticationFilter filter = new DigestAuthenticationFilter(){

            @Override
            public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                    throws IOException, ServletException {
                req.setAttribute(GeoServerSecurityFilter.AUTHENTICATION_ENTRY_POINT_HEADER, aep);
                super.doFilter(req, res, chain);
                    
            }            
        };

        filter.setCreateAuthenticatedToken(true);
        filter.setPasswordAlreadyEncoded(true);
        

        filter.setAuthenticationEntryPoint(aep);
        
        
        HttpDigestUserDetailsServiceWrapper wrapper = 
                new HttpDigestUserDetailsServiceWrapper(
                        getSecurityManager().loadUserGroupService(authConfig.getUserGroupServiceName()),
                        Charset.defaultCharset()); 
        filter.setUserDetailsService(wrapper);
        
        filter.afterPropertiesSet();
        getNestedFilters().add(filter);        
    }
    
    @Override
    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return aep;
    }

}
