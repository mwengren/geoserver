/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.config;

import org.geoserver.security.GeoServerRoleConverter;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.filter.GeoServerRequestHeaderAuthenticationFilter;

/**
 * {@link GeoServerRequestHeaderAuthenticationFilter} configuration object.
 * 
 * <p>
 * {@link #getPrincipalHeaderAttribute()} is the name of the header 
 * containing the principal name.
 * </p>
 *<p>
 * {@link #getRoleSource()} determines how to calculate the roles:
 * <ol>
 * <li>{@link RoleSource#UserGroupService} - Roles are calculated using the named user group service
 *     {@link #getUserGroupServiceName()}</li>
 * <li>{@link RoleSource#RoleService} - Roles are calculated using the named role service
 *     {@link #getRoleServiceName()}. If no role service is given, the default is 
 *     {@link GeoServerSecurityManager#getActiveRoleService()}</li>
 * <li>{@link RoleSource#Header} - Roles are calculated using the content of 
 *     {@link #getRolesHeaderAttribute()} parsed by {@link #getRoleConverterName()}. if no converter 
 *     is given, roles are parsed by the default converter {@link GeoServerRoleConverter}</li>
 * 
 * @author christian
 */
public class RequestHeaderAuthenticationFilterConfig extends SecurityFilterConfig 
    implements SecurityAuthFilterConfig {

    private RoleSource roleSource;
    private String principalHeaderAttribute;
    private String rolesHeaderAttribute;
    private String userGroupServiceName;
    private String roleConverterName;
    private String roleServiceName;

    
    public static enum  RoleSource{
        Header,UserGroupService,RoleService;
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

    @Override
    public  boolean providesAuthenticationEntryPoint() {
        return true;
    }

    public String getRoleServiceName() {
        return roleServiceName;
    }

    public void setRoleServiceName(String roleServiceName) {
        this.roleServiceName = roleServiceName;
    }

}
