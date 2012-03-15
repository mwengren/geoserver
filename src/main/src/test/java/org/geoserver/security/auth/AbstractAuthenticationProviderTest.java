/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.auth;

import java.util.ArrayList;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerAuthenticationProvider;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerRoleStore;
import org.geoserver.security.GeoServerSecurityFilterChain;
import org.geoserver.security.GeoServerSecurityFilterChainProxy;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.GeoServerUserGroupStore;
import org.geoserver.security.config.SecurityManagerConfig;
import org.geoserver.security.config.SecurityRoleServiceConfig;
import org.geoserver.security.config.SecurityUserGroupServiceConfig;
import org.geoserver.security.config.UsernamePasswordAuthenticationProviderConfig;
import org.geoserver.security.config.impl.MemoryRoleServiceConfigImpl;
import org.geoserver.security.config.impl.MemoryUserGroupServiceConfigImpl;
import org.geoserver.security.impl.AbstractSecurityServiceTest;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.impl.MemoryRoleService;
import org.geoserver.security.impl.MemoryUserGroupService;
import org.geoserver.security.password.PasswordValidator;
import org.springframework.security.core.Authentication;

import com.mockrunner.mock.web.MockHttpServletRequest;

public abstract class AbstractAuthenticationProviderTest extends AbstractSecurityServiceTest {

    
    public final static String testUserName = "user1";
    public final static String testPassword = "pw1";
    public final static String rootRole = "RootRole";
    public final static String derivedRole = "DerivedRole";
    public final static String pattern = "/foo/**";
    public final static String testProviderName = "testAuthenticationProvider";

    @Override
    protected void setUpInternal() throws Exception {
        super.setUpInternal();
        createServices();
    }
    
    protected void createServices() throws Exception{
        
        GeoServerRoleService rservice = createRoleService("rs1");
        GeoServerRoleStore rstore = rservice.createStore();
        GeoServerRole root, derived;
        rstore.addRole(root=rstore.createRoleObject(rootRole));
        rstore.addRole(derived=rstore.createRoleObject(derivedRole));
        rstore.setParentRole(derived, root);
        rstore.associateRoleToUser(derived, testUserName);
        rstore.store();
        
        SecurityManagerConfig mconfig = getSecurityManager().loadSecurityConfig();
        mconfig.setRoleServiceName("rs1");
        getSecurityManager().saveSecurityConfig(mconfig);
        
        GeoServerUserGroupService ugservice = createUserGroupService("ug1");
        GeoServerUserGroupStore ugstore = ugservice.createStore();
        GeoServerUser u1 = ugstore.createUserObject(testUserName, testPassword, true);
        ugstore.addUser(u1);
        GeoServerUser u2 = ugstore.createUserObject("abc@xyz.com", "abc", true);
        ugstore.addUser(u2);

        ugstore.store();
        
        GeoServerAuthenticationProvider prov = createAuthProvider(testProviderName, ugservice.getName());
        prepareAuthProviders(prov.getName());        
        
    }
    
    protected void insertAnonymousFilter(String beforName) throws Exception{
        SecurityManagerConfig mconfig = getSecurityManager().loadSecurityConfig();
        mconfig.getFilterChain().insertBefore(pattern,GeoServerSecurityFilterChain.ANONYMOUS_FILTER,beforName);
        getSecurityManager().saveSecurityConfig(mconfig);        
    }
    
    protected void removeAnonymousFilter() throws Exception{
        SecurityManagerConfig mconfig = getSecurityManager().loadSecurityConfig();
        mconfig.getFilterChain().getFilterMap().get(pattern).remove(GeoServerSecurityFilterChain.ANONYMOUS_FILTER);
        getSecurityManager().saveSecurityConfig(mconfig);        
    }

    
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
    
    protected void updateUser(String ugService, String userName,boolean enabled) throws Exception {
        GeoServerUserGroupService ugservice = getSecurityManager().loadUserGroupService(ugService);
        GeoServerUserGroupStore ugstore = ugservice.createStore();
        GeoServerUser u1 = ugstore.getUserByUsername(userName);
        u1.setEnabled(enabled);
        ugstore.updateUser(u1);
        ugstore.store();
    }
    
    GeoServerSecurityFilterChainProxy getProxy() {
        return GeoServerExtensions.bean(GeoServerSecurityFilterChainProxy.class);
    }
    
    @Override
    protected MockHttpServletRequest createRequest(String url) {
        MockHttpServletRequest request = super.createRequest(url);
        request.setPathInfo(null);
        request.setQueryString(null);
        return request;        
    }

}
