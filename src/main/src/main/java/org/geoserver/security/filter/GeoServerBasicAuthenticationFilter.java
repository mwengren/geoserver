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

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.BasicAuthenticationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Named Basic Authentication Filter
 * 
 * @author mcr
 *
 */
public class GeoServerBasicAuthenticationFilter extends GeoServerCompositeFilter {
    private BasicAuthenticationEntryPoint aep; 
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
        
        aep= new BasicAuthenticationEntryPoint();
        aep.setRealmName(GeoServerSecurityManager.REALM);
        try {
            aep.afterPropertiesSet();
        } catch (Exception e) {
            throw new IOException(e);
        }
        
        BasicAuthenticationFilterConfig authConfig = 
                (BasicAuthenticationFilterConfig) config;
        
        BasicAuthenticationFilter filter = new BasicAuthenticationFilter() {

            @Override
            public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                    throws IOException, ServletException {
                
                req.setAttribute(GeoServerSecurityFilter.AUTHENTICATION_ENTRY_POINT_HEADER, aep);
                super.doFilter(req, res, chain);
            }            
        };
        filter.setAuthenticationManager(getSecurityManager());
        filter.setIgnoreFailure(false);
        filter.setAuthenticationEntryPoint(aep);                

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
    
    @Override
    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return aep;
    }

}
