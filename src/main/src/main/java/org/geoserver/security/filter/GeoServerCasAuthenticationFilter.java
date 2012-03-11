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

import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.config.CasAuthenticationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;

/**
 * Named Cas Authentication Filter
 * 
 * @author mcr
 *
 */
public class GeoServerCasAuthenticationFilter extends GeoServerCompositeFilter {
    private CasAuthenticationEntryPoint aep; 
    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);

                
        CasAuthenticationFilterConfig authConfig = 
                (CasAuthenticationFilterConfig) config;
        
        ServiceProperties sp = new ServiceProperties();
        sp.setSendRenew(authConfig.isSendRenew());
        sp.setService(authConfig.getService());
        try {
            sp.afterPropertiesSet();
        } catch (Exception e) {
            throw new IOException(e);
        }
        
        aep= new CasAuthenticationEntryPoint();
        aep.setLoginUrl(authConfig.getLoginUrl());
        aep.setServiceProperties(sp);
        try {
            aep.afterPropertiesSet();
        } catch (Exception e) {
            throw new IOException(e);
        }
        
        
        
        CasAuthenticationFilter filter = new CasAuthenticationFilter() {

            @Override
            public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
                    throws IOException, ServletException {
                
                req.setAttribute(GeoServerSecurityFilter.AUTHENTICATION_ENTRY_POINT_HEADER, aep);
                super.doFilter(req, res, chain);
            }            
        };
        
        filter.setAuthenticationManager(getSecurityManager());
        filter.setAllowSessionCreation(false);
        
        // TODO,add the authentication provider to the security manager
        
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setKey(config.getName());
        GeoServerUserGroupService ugService = getSecurityManager().loadUserGroupService(authConfig.getUserGroupServiceName());
        provider.setAuthenticationUserDetailsService(new UserDetailsByNameServiceWrapper(ugService));
        provider.setServiceProperties(sp);
        Cas20ServiceTicketValidator ticketValidator = new Cas20ServiceTicketValidator(authConfig.getTicketValidatorUrl());
        provider.setTicketValidator(ticketValidator);
        
        
        filter.afterPropertiesSet();
        getNestedFilters().add(filter);        
    }
    
}
