/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.config;

import org.geoserver.security.filter.GeoServerExceptionTranslationFilter;
import org.geoserver.security.filter.GeoServerSecurityFilter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;


/**
 * Configuration for exception translation filter
 * 
 * The property {@link #authenticationEntryPointName} is the Spring name 
 * of a {@link AuthenticationEntryPoint} object which is needed in case
 * of an {@link AuthenticationException}
 * 
 * IMPORTANT: if no authentication entry point is given, {@link GeoServerExceptionTranslationFilter}
 * uses the entry point found in the servlet request  attribute 
 * {@link GeoServerSecurityFilter#AUTHENTICATION_ENTRY_POINT_HEADER}
 * 
 * The property {@link #accessDeniedErrorPage} is optional and needed in 
 * case of an {@link AccessDeniedException}. Geoserver default is
 * <b>/accessDenied.jsp</b>
 * 
 * @author christian
 *
 */
public class ExceptionTranslationFilterConfig extends NamedFilterConfig {

    private static final long serialVersionUID = 1L;

    private String authenticationEntryPointName;
    private String accessDeniedErrorPage;
    
    public String getAuthenticationEntryPointName() {
        return authenticationEntryPointName;
    }
    public void setAuthenticationEntryPointName(String authenticationEntryPointName) {
        this.authenticationEntryPointName = authenticationEntryPointName;
    }
    public String getAccessDeniedErrorPage() {
        return accessDeniedErrorPage;
    }
    public void setAccessDeniedErrorPage(String accessDeniedErrorPage) {
        this.accessDeniedErrorPage = accessDeniedErrorPage;
    }    
}
