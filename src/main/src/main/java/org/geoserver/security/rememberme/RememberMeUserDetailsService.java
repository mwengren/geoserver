/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org.  All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */
package org.geoserver.security.rememberme;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * User details implementation for remember me services that handles usernames of the form 
 * &lt;actualUserName>@&lt;userGroupServiceName>.
 * <p>
 * The user group component is used to load the appropriate {@link GeoServerUserGroupService}
 * to look up the user name against.  
 * </p>
 * @author Justin Deoliveira, OpenGeo
 *
 */
public class RememberMeUserDetailsService implements UserDetailsService {

    /** pattern used to parse username@userGroupServiceName token */
    static Pattern TOKEN_PATTERN = Pattern.compile("(.*[^\\\\])@(.*)"); 
            
    GeoServerSecurityManager securityManager;

    public RememberMeUserDetailsService(GeoServerSecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException,
            DataAccessException {
        Matcher m = TOKEN_PATTERN.matcher(username);
        if (!m.matches()) {
            throw new UsernameNotFoundException("No delimiter '@' found in username: " + username);
        }

        String user = m.group(1).replace("\\@", "@");
        String service = m.group(2);

        try {
            GeoServerUserGroupService ugService = securityManager.loadUserGroupService(service);
            return ugService.loadUserByUsername(user);
        } catch (IOException e) {
            throw new DataAccessException("Error loading user group service " + service, e) {};
        }
    }
}