/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.RequestKey;
import org.springframework.security.web.util.AntUrlPathMatcher;
import org.springframework.security.web.util.UrlMatcher;

/**
 * Justin, nasty hack to get rid of the spring bean
 * "filterSecurityInterceptor";
 * I think, there is a better was to solve this.
 * 
 * 
 * @author mcr
 *
 */
public class GeoServerSecurityMetadataSource extends DefaultFilterInvocationSecurityMetadataSource {

    static UrlMatcher matcher;
    static LinkedHashMap<RequestKey, Collection<ConfigAttribute>> requestMap;
    static {
        matcher = new AntUrlPathMatcher(true);
        requestMap= new LinkedHashMap<RequestKey, Collection<ConfigAttribute>>();
        RequestKey key = new RequestKey("/config/**");
        List<ConfigAttribute> list = new ArrayList<ConfigAttribute>();
        list.add(new SecurityConfig("ROLE_ADMINISTRATOR"));
        requestMap.put(key,list);

        key = new RequestKey("/**");
        list = new ArrayList<ConfigAttribute>();
        list.add(new SecurityConfig("IS_AUTHENTICATED_ANONYMOUSLY"));
        requestMap.put(key,list);                
    };
    
    public GeoServerSecurityMetadataSource() {
        super(matcher,requestMap);
        /*
        <sec:intercept-url pattern="/config/**" access="ROLE_ADMINISTRATOR"/>
        <sec:intercept-url pattern="/**" access="IS_AUTHENTICATED_ANONYMOUSLY"/>
        */
        
    }    
}
