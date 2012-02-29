/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org.  All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */


package org.geoserver.security.password;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Wrapper class needed if the password is needed in
 * a modified form (plain text, 
 * prepared for message digest authentication,..)
 *  
 * @author mcr
 *
 */
public class UserDetailsPasswordWrapper implements UserDetails{

    private static final long serialVersionUID = 1L;

    public UserDetailsPasswordWrapper(UserDetails details, String password) {
        this.details=details;
        this.password=password;
    }
    
    private String password;
    
    protected UserDetails details;

    public Collection<GrantedAuthority> getAuthorities() {
        return details.getAuthorities();
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return details.getUsername();
    }

    public boolean isAccountNonExpired() {
        return details.isAccountNonExpired();
    }

    public boolean isAccountNonLocked() {
        return details.isAccountNonLocked();
    }

    public boolean isCredentialsNonExpired() {
        return details.isCredentialsNonExpired();
    }

    public boolean isEnabled() {
        return details.isEnabled();
    }
}
