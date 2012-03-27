/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.cas;

import org.geoserver.security.auth.AuthenticationCache;
import org.geoserver.security.auth.AuthenticationCacheImpl;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.StatelessTicketCache;

/**
 * Implementation of {@link StatelessTicketCache} using the global
 * Geoserver {@link AuthenticationCache}
 * 
 * @author christian
 *
 */
public class GeoserverCasStatelessTicketCache implements StatelessTicketCache {

    protected AuthenticationCache authCache;
    protected String filterName;

    public GeoserverCasStatelessTicketCache(String filterName, AuthenticationCache authCache) {
        this.filterName=filterName;
        this.authCache = authCache;
    }
    @Override
    public CasAuthenticationToken getByTicketId(String serviceTicket) {
        return (CasAuthenticationToken) authCache.get(filterName,serviceTicket);
    }

    @Override
    public void putTicketInCache(CasAuthenticationToken token) {
        authCache.put(filterName,token.getCredentials().toString(), token);
    }

    @Override
    public void removeTicketFromCache(CasAuthenticationToken token) {
        removeTicketFromCache(token.getCredentials().toString());
    }

    @Override
    public void removeTicketFromCache(String serviceTicket) {
        authCache.remove(filterName,serviceTicket);
    }

}
