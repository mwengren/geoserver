/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.util.ArrayList;
import java.util.List;

import org.geoserver.security.impl.GeoServerRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * anonymous authentication filter injecting  {@link GeoServerRole#ANONYMOUS_ROLE}
 * 
 * This is singleton and not a named security service 
 * 
 * @author mcr
 *
 */
public class GeoServerAnonymousAuthenticationFilter extends AnonymousAuthenticationFilter {

    
    @Override
    public void setUserAttribute(UserAttribute userAttributeDefinition) {
        List<GrantedAuthority> list = new ArrayList<GrantedAuthority>();
        list.add(GeoServerRole.ANONYMOUS_ROLE);
        userAttributeDefinition.setAuthorities(list);
        super.setUserAttribute(userAttributeDefinition);
    }


}
