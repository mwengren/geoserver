/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */

package org.geoserver.security.auth;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;

import com.ibm.jvm.util.ByteArrayOutputStream;


/**
 * Implementation for testing, no timing 
 * 
 * @author mcr
 *
 */
public class TestingAuthenticationCache implements AuthenticationCache {

    Map<String,Map<String,byte[]>> cache =
            new HashMap<String, Map<String,byte[]>>();
    
    @Override
    public void removeAll() {
        cache.clear();
    }

    @Override
    public void removeAll(String filterName) {
        cache.remove(filterName);
    }

    @Override
    public void remove(String filterName, String cacheKey) {
        Map<String,byte[]> map = cache.get(filterName);
        if (map!=null)
            map.remove(cacheKey);
        
    }

    @Override
    public Authentication get(String filterName, String cacheKey) {
        Map<String,byte[]> map = cache.get(filterName);
        if (map!=null)
            return deserializeAuthentication(map.get(cacheKey));
        else
            return null;
    }

    @Override
    public void put(String filterName, String cacheKey, Authentication auth,
            Integer timeToIdleSeconds, Integer timeToLiveSeconds) {        
        put(filterName,cacheKey,auth);
    }

    @Override
    public void put(String filterName, String cacheKey, Authentication auth) {
        Map<String,byte[]> map = cache.get(filterName);
        if (map==null) {
            map = new HashMap<String,byte[]>();
            cache.put(filterName, map);
        }
        map.put(cacheKey, serializeAuthentication(auth));
    }

    Authentication deserializeAuthentication(byte[]bytes) {
        if (bytes==null) return null;
        try {
            ByteArrayInputStream bin = new ByteArrayInputStream(bytes);
            ObjectInputStream in = new ObjectInputStream(bin);
            Authentication auth = (Authentication)in.readObject();
            in.close();
            return auth;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }        
    }
    
    public  byte[] serializeAuthentication(Authentication auth) {
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream ();
            ObjectOutputStream out = new ObjectOutputStream(bout);
            out.writeObject(auth);
            out.close();
            return bout.toByteArray();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
