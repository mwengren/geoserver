/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */


package org.geoserver.security.filter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.logging.Level;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.geoserver.security.config.BasicAuthenticationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * Abstract base class for pre-authentication filters
 * 
 * @author christian
 *
 */
public abstract class GeoServerAbstractPreAuthenticationFilter extends GeoServerSecurityFilter {

    static public class NoPrincipalException extends AuthenticationException {

        private static final long serialVersionUID = 1L;

        public NoPrincipalException(String msg, Object extraInformation) {
            super(msg, extraInformation);
            
        }

        public NoPrincipalException(String msg, Throwable t) {
            super(msg, t);
            
        }

        public NoPrincipalException(String msg) {
            super(msg);
            
        }        
    };
    
    private AuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private boolean authenticationRequired;
    
    
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
                        
        BasicAuthenticationFilterConfig authConfig = 
                (BasicAuthenticationFilterConfig) config;
        
        authenticationRequired=authConfig.isAuthenticationRequired();
                
    }

    
    /**
     * Try to authenticate if there is no authenticated principal
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (SecurityContextHolder.getContext().getAuthentication()==null) {
            doAuthenticate((HttpServletRequest) request, (HttpServletResponse) response);
        }

        chain.doFilter(request, response);        
    }
            

    /**
     * subclasses should return the principal, 
     * <code>null</code> if no principal was authenticated 
     * 
     * @param request
     * @return
     */
    abstract protected String getPreAuthenticatedPrincipal(HttpServletRequest request);
    
    /**
     * subclasses should return the roles for the principal
     * obtained by {@link #getPreAuthenticatedPrincipal(HttpServletRequest)}
     * 
     * @param request
     * @param principal
     * @return
     */
    abstract protected Collection<GeoServerRole> getRoles(HttpServletRequest request, String principal) throws IOException;
    
    /**
     * Used if {@link #isAuthenticationRequired()} is <code>true</code>
     * and no principal is set.
     * 
     * @return
     */
    abstract protected NoPrincipalException createNoPrincipalException(HttpServletRequest request);

    
    /**
     * Try to authenticate and adds {@link GeoServerRole#AUTHENTICATED_ROLE}
     * Takes care of the special user named {@link GeoServerUser#ROOT_USERNAME}
     * 
     * @param request
     * @param response
     */
    private void doAuthenticate(HttpServletRequest request, HttpServletResponse response) {

        String principal = getPreAuthenticatedPrincipal(request);
        

        if (principal == null) {            
            LOGGER.log(Level.FINE,"No pre-authenticated principal found in request");
            if (isAuthenticationRequired())
                throw createNoPrincipalException(request);
            return;
        }
        
        LOGGER.log(Level.FINE,"preAuthenticatedPrincipal = " + principal + ", trying to authenticate");
        
        PreAuthenticatedAuthenticationToken result = null;
        if (GeoServerUser.ROOT_USERNAME.equals(principal)) {
            result = new PreAuthenticatedAuthenticationToken(principal, null, Collections.singleton(GeoServerRole.ADMIN_ROLE));            
        } else {
            Collection<GeoServerRole> roles=null;
            try {
                roles = getRoles(request, principal);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            if (roles.contains(GeoServerRole.AUTHENTICATED_ROLE)==false)
                roles.add(GeoServerRole.AUTHENTICATED_ROLE);
            result = new PreAuthenticatedAuthenticationToken(principal, null, roles);
            
        }
                                                
        result.setDetails(authenticationDetailsSource.buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(result);                        
    }

    
    public AuthenticationDetailsSource getAuthenticationDetailsSource() {
        return authenticationDetailsSource;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public boolean isAuthenticationRequired() {
        return authenticationRequired;
    }

    public void setAuthenticationRequired(boolean authenticationRequired) {
        this.authenticationRequired = authenticationRequired;
    }
    
    
}
