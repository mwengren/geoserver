/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.config;


/**
 * Configuration for basic authentication
 * 
 * @author mcr
 *
 */
public class BasicAuthenticationFilterConfig extends BaseSecurityNamedServiceConfig {

    private static final long serialVersionUID = 1L;
    private String rememberMeServiceName;
    private boolean ignoreFailure = false;
    
    public String getRememberMeServiceName() {
        return rememberMeServiceName;
    }
    public void setRememberMeServiceName(String rememberMeServiceName) {
        this.rememberMeServiceName = rememberMeServiceName;
    }
    public boolean isIgnoreFailure() {
        return ignoreFailure;
    }
    public void setIgnoreFailure(boolean ignoreFailure) {
        this.ignoreFailure = ignoreFailure;
    }
    
}
