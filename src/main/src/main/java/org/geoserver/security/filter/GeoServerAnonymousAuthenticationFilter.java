/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.impl.GeoServerUser;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;

/**
 * Anonymous authentication filter
 * 
 * @author mcr
 *
 */
public class GeoServerAnonymousAuthenticationFilter extends GeoServerSecurityFilter {

    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
    }
       
    private AuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();


    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            SecurityContextHolder.getContext().setAuthentication(createAuthentication((HttpServletRequest) req));
        }

        chain.doFilter(req, res);
    }


    protected Authentication createAuthentication(HttpServletRequest request) {
        GeoServerUser anonymous = GeoServerUser.createAnonymous();
        List<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
        roles.addAll(anonymous.getAuthorities());
        AnonymousAuthenticationToken auth = new AnonymousAuthenticationToken("geoserver", 
                anonymous.getUsername(),roles);
        auth.setDetails(authenticationDetailsSource.buildDetails(request));
        return auth;
    }


    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }
}
