/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.auth;

import org.geoserver.platform.GeoServerExtensions;
import org.springframework.security.core.Authentication;

/**
 * @author mcr
 *
 * TODO, Justin, how to integrate correctly ?
 *
 * Null implementation doing nothing
 */
public class AuthenticationCacheImpl implements AuthenticationCache {

    
    static AuthenticationCache Singleton;
    
    public static AuthenticationCache get() {
        if (Singleton!=null)
            return Singleton;
        
        Singleton = GeoServerExtensions.bean(AuthenticationCache.class);
        
        if  (Singleton==null)
            Singleton=new AuthenticationCacheImpl();
        
        return Singleton;
    }
    
    @Override
    public void removeAll() {
    }

    @Override
    public void removeAll(String filterName) {
    }

    @Override
    public void remove(String filterName, String cacheKey) {
    }

    @Override
    public Authentication get(String filterName, String cacheKey) {
        return null;
    }

    @Override
    public void put(String filterName, String cacheKey, Authentication auth,
            Integer timeToIdleSeconds, Integer timeToLiveSeconds) {
    }

    @Override
    public void put(String filterName, String cacheKey, Authentication auth) {
    }
}
