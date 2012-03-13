/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.config;


/**
 * Configuration for basic authentication
 * 
 * if {@link #useRememberMe} is <code>true</code>, the
 * filter registers a successful authentication in the 
 * global remember me service 
 * 
 * @author mcr
 *
 */
public class BasicAuthenticationFilterConfig extends NamedFilterConfig {

    private static final long serialVersionUID = 1L;
    private boolean useRememberMe;
    
    public boolean isUseRememberMe() {
        return useRememberMe;
    }
    public void setUseRememberMe(boolean useRememberMe) {
        this.useRememberMe = useRememberMe;
    }
    
        
}
