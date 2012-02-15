/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */


package org.geoserver.security.impl;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerRoleConverter;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.SecurityManagerConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Servlet filter for sending the roles (and role parameters) of the authenticated
 * principal to client
 * 
 * {@link SecurityManagerConfig#isIncludingRolesInResponse()} must be true
 * and {@link SecurityManagerConfig#getHttpResponseHeaderAttrForIncludedRoles()} must
 * contain the header attribute name
 * 
 * @author mcr
 *
 */
public class GeoServerRoleFilter implements Filter {
    
    GeoServerSecurityManager manager;
    GeoServerRoleConverter converter;
    
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        chain.doFilter(request, response);
        
        if (manager == null)
            manager = GeoServerExtensions.bean(GeoServerSecurityManager.class);
        
        SecurityManagerConfig config = manager.getSecurityConfig();
        if (config.isIncludingRolesInResponse()) {
            SecurityContext context =SecurityContextHolder.getContext();
            if (context!=null) {
                Authentication auth = context.getAuthentication();
                if (auth!=null) {
                    String roleString = converter.
                            convertRolesToString(auth.getAuthorities());
                    ((HttpServletResponse)response).setHeader(
                            config.getHttpResponseHeaderAttrForIncludedRoles(),
                            roleString);
                }
            }
        }
        
    }

    @Override
    public void destroy() {
        manager=null;
    }

    public GeoServerRoleConverter getConverter() {
        return converter;
    }

    public void setConverter(GeoServerRoleConverter converter) {
        this.converter = converter;
    }

}
