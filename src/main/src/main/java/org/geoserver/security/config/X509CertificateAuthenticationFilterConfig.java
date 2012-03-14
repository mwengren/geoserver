/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.config;

import org.geoserver.security.GeoServerSecurityManager;

/**
 * Configuration for pre authentication using a x509 certificate
 * {@link #getRoleSource()} determines how to calculate the roles
 * 
 * 1) {@link RoleSource#UGService}
 * Roles are calculated using the named user group service
 * {@link #getUserGroupServiceName()}
 * 
 * 2) {@link RoleSource#RoleService}
 * Roles are calculated using the named role service
 * {@link #getRoleServiceName()}. If no role service is given, the 
 * default is {@link GeoServerSecurityManager#getActiveRoleService()}
 * 
 * @author christian
 *
 */
public class X509CertificateAuthenticationFilterConfig extends NamedFilterConfig {

    private RoleSource roleSource;
    private String userGroupServiceName;
    private String roleServiceName;

    
    public static enum  RoleSource{
        UGService,RoleService;
    } ;
    
    private static final long serialVersionUID = 1L;
    
    public RoleSource getRoleSource() {
        return roleSource;
    }

    public void setRoleSource(RoleSource roleSource) {
        this.roleSource = roleSource;
    }

    @Override
    public  boolean providesAuthenticationEntryPoint() {
        return true;
    }



    public String getUserGroupServiceName() {
        return userGroupServiceName;
    }

    public void setUserGroupServiceName(String userGroupServiceName) {
        this.userGroupServiceName = userGroupServiceName;
    }



    public String getRoleServiceName() {
        return roleServiceName;
    }

    public void setRoleServiceName(String roleServiceName) {
        this.roleServiceName = roleServiceName;
    }

}
