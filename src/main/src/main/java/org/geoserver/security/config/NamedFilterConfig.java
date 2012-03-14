/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.config;

import org.geoserver.security.filter.GeoServerSecurityFilter;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Abstract base class for all filter configurations
 * 
 * @author mcr
 *
 */
public abstract class NamedFilterConfig extends BaseSecurityNamedServiceConfig {

    private static final long serialVersionUID = 1L;
    
    /**
     * 
     * 
     * @return true if the corresponding filter provides an
     * {@link AuthenticationEntryPoint} object. 
     * 
     * if <code>true</code>, the method
     * {@link GeoServerSecurityFilter#getAuthenticationEntryPoint()}
     * must not return <code>null</code>
     */
    public  boolean providesAuthenticationEntryPoint() {
        return false;
    }

}
