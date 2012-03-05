/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.config;

abstract public class BaseAuthenticationFilterConfig extends BaseFilterConfig {

    private static final long serialVersionUID = 1L;
    
    /**
     * Continue in the filter chain in case
     * of an unsuccessful authentication
     * 
     * @return
     */
    abstract boolean isAuthenticationRequired(); 

}
