/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.config;

import org.geoserver.security.GeoServerSecurityManager;

/**
 * Configuration for a J2EE  authentication scenario
 * 
 * {@link #roleServiceName} is optional, 
 * default is {@link GeoServerSecurityManager#getActiveRoleService()} 
 * 
 * 
 * @author christian
 *
 */
public class J2eeAuthenticationFilterConfig extends BaseAuthenticationFilterConfig {

    private static final long serialVersionUID = 1L;
    
    private String roleServiceName;
    private boolean authenticationRequired;

    public boolean isAuthenticationRequired() {
        return authenticationRequired;
    }

    public void setAuthenticationRequired(boolean authenticationRequired) {
        this.authenticationRequired = authenticationRequired;
    }

    public String getRoleServiceName() {
        return roleServiceName;
    }

    public void setRoleServiceName(String roleServiceName) {
        this.roleServiceName = roleServiceName;
    }

}
