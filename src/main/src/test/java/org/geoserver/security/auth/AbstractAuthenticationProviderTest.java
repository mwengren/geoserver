/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.auth;

import java.util.ArrayList;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerAuthenticationProvider;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerSecurityFilterChain;
import org.geoserver.security.GeoServerSecurityFilterChainProxy;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.config.SecurityManagerConfig;
import org.geoserver.security.config.SecurityRoleServiceConfig;
import org.geoserver.security.config.SecurityUserGroupServiceConfig;
import org.geoserver.security.config.UsernamePasswordAuthenticationProviderConfig;
import org.geoserver.security.config.impl.MemoryRoleServiceConfigImpl;
import org.geoserver.security.config.impl.MemoryUserGroupServiceConfigImpl;
import org.geoserver.security.impl.AbstractSecurityServiceTest;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.MemoryRoleService;
import org.geoserver.security.impl.MemoryUserGroupService;
import org.geoserver.security.password.PasswordValidator;
import org.springframework.security.core.Authentication;

public abstract class AbstractAuthenticationProviderTest extends AbstractSecurityServiceTest {


    public GeoServerAuthenticationProvider createAuthProvider(String name, String userGroupServiceName) 
        throws Exception {
        UsernamePasswordAuthenticationProviderConfig config = new
                UsernamePasswordAuthenticationProviderConfig();
        config.setClassName(UsernamePasswordAuthenticationProvider.class.getName());
        config.setUserGroupServiceName(userGroupServiceName);
        config.setName(name);
        getSecurityManager().saveAuthenticationProvider(config);
        return getSecurityManager().loadAuthenticationProvider(name);        
    }
    
    @Override
    public GeoServerRoleService createRoleService(String name) throws Exception {
        SecurityRoleServiceConfig config = getRoleConfig(name);
        getSecurityManager().saveRoleService(config);
        return getSecurityManager().loadRoleService(name);        
    }
    
    
    public MemoryRoleServiceConfigImpl getRoleConfig(String name) {
        MemoryRoleServiceConfigImpl config = new MemoryRoleServiceConfigImpl();
        config.setName(name);
        config.setClassName(MemoryRoleService.class.getName());
        config.setAdminRoleName(GeoServerRole.ADMIN_ROLE.getAuthority());
        config.setToBeEncrypted("encryptme");
        return config;
        
    }

    @Override
    public GeoServerUserGroupService createUserGroupService(String name) throws Exception {
        return createUserGroupService(name, getPBEPasswordEncoder().getName());

    }
    
    public GeoServerUserGroupService createUserGroupService(String name,String passwordEncoderName) throws Exception {
        SecurityUserGroupServiceConfig config =  getUserGroupConfg(name, passwordEncoderName);                 
        getSecurityManager().saveUserGroupService(config/*,isNewUGService(name)*/);
        return getSecurityManager().loadUserGroupService(name);

    }
    

    public MemoryUserGroupServiceConfigImpl getUserGroupConfg(String name, String passwordEncoderName) {
        MemoryUserGroupServiceConfigImpl config = new MemoryUserGroupServiceConfigImpl();         
        config.setName(name);
        config.setClassName(MemoryUserGroupService.class.getName());
        config.setPasswordEncoderName(passwordEncoderName);
        config.setPasswordPolicyName(PasswordValidator.DEFAULT_NAME);
        config.setToBeEncrypted("encryptme");
        return config;
    }

            
    public void checkForAuthenticatedRole(Authentication auth) {
        assertTrue(auth.getAuthorities().contains(GeoServerRole.AUTHENTICATED_ROLE));
    }

    protected void prepareAuthProviders(String... authProviderNames) throws Exception{
       SecurityManagerConfig config = getSecurityManager().getSecurityConfig();
       config.getAuthProviderNames().clear();
       for (String n : authProviderNames)
           config.getAuthProviderNames().add(n);
       getSecurityManager().saveSecurityConfig(config);        
    }

    protected void prepareFiterChain(String pattern, String... filterNames) throws Exception{
        SecurityManagerConfig config = getSecurityManager().getSecurityConfig();
        if (config.getFilterChain().getAntPatterns().contains(pattern)) {
            config.getFilterChain().getAntPatterns().remove(pattern);
            config.getFilterChain().getFilterMap().remove(pattern);
        }
       config.getFilterChain().getAntPatterns().add(config.getFilterChain().getAntPatterns().size()-2, pattern);
       ArrayList<String> filters = new ArrayList<String>();
       
       for (String filterName : filterNames)
           filters.add(filterName);
       
       config.getFilterChain().getFilterMap().put(pattern,filters);
       getSecurityManager().saveSecurityConfig(config);
                           
    }
    
    GeoServerSecurityFilterChainProxy getProxy() {
        return GeoServerExtensions.bean(GeoServerSecurityFilterChainProxy.class);
    }
}
