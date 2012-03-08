/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.config;

import org.geoserver.security.GeoServerRoleConverter;
import org.geoserver.security.GeoServerSecurityManager;

/**
 * Configuration for pre authentication using http request headers
 * 
 * {@link #getPrincipalHeaderAttribute()} is the name of the header 
 * containing the principal name.
 * 
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
 * 3) {@link RoleSource#HEADER}
 * Roles are calculated using the content of {@link #getRolesHeaderAttribute()}
 * parsed by {@link #getRoleConverterName()}. if no converter is given,
 * roles are parsed by the default converter {@link GeoServerRoleConverter}
 *  
 * 
 * @author christian
 *
 */
public class RequestHeaderAuthenticationFilterConfig extends BaseSecurityNamedServiceConfig {

    private RoleSource roleSource;
    private String principalHeaderAttribute;
    private String rolesHeaderAttribute;
    private String userGroupServiceName;
    private String roleConverterName;
    private String roleServiceName;

    
    public static enum  RoleSource{
        HEADER,UGService,RoleService;
    } ;
    
    private static final long serialVersionUID = 1L;
    
    public RoleSource getRoleSource() {
        return roleSource;
    }

    public void setRoleSource(RoleSource roleSource) {
        this.roleSource = roleSource;
    }

    public String getPrincipalHeaderAttribute() {
        return principalHeaderAttribute;
    }

    public void setPrincipalHeaderAttribute(String principalHeaderAttribute) {
        this.principalHeaderAttribute = principalHeaderAttribute;
    }

    public String getRolesHeaderAttribute() {
        return rolesHeaderAttribute;
    }

    public void setRolesHeaderAttribute(String rolesHeaderAttribute) {
        this.rolesHeaderAttribute = rolesHeaderAttribute;
    }

    public String getUserGroupServiceName() {
        return userGroupServiceName;
    }

    public void setUserGroupServiceName(String userGroupServiceName) {
        this.userGroupServiceName = userGroupServiceName;
    }

    public String getRoleConverterName() {
        return roleConverterName;
    }

    public void setRoleConverterName(String roleConverterName) {
        this.roleConverterName = roleConverterName;
    }


    public String getRoleServiceName() {
        return roleServiceName;
    }

    public void setRoleServiceName(String roleServiceName) {
        this.roleServiceName = roleServiceName;
    }

}
