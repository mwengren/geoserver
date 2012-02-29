/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org.  All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */
package org.geoserver.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.geoserver.security.auth.GeoServerRootAuthenticationProvider;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.password.GeoServerPasswordEncoder;
import org.geoserver.security.password.PasswordEncodingType;
import org.geoserver.security.password.UserDetailsPasswordWrapper;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.codec.Hex;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;

/**
 * {@link UserDetailsService} implementation to be used for 
 * HTTP digest authentication
 * 
 * {@link UserDetails} objects have their password alreay md5a1 encoded.
 * 
 *  {@link DigestAuthenticationFilter#setPasswordAlreadyEncoded(boolean)} must
 *  be called with a value of <code>true</code>
 * 
 * @author christian
 *
 */
public class HttpDigestUserDetailsServiceWrapper implements UserDetailsService {
    
    private GeoServerSecurityManager manager;
    protected GeoServerUserGroupService service;
    protected String charSet;
    protected final char[] delimArray= new char[] {':' };
    protected MessageDigest digest;
    protected GeoServerPasswordEncoder enc;
    
    public HttpDigestUserDetailsServiceWrapper(GeoServerUserGroupService service,String charSet) {
       this.service= service;
       this.charSet=charSet;
       manager = service.getSecurityManager();

       enc = service.getSecurityManager().loadPasswordEncoder(service.getPasswordEncoderName());
       if ((enc.getEncodingType()==PasswordEncodingType.PLAIN ||
                  enc.getEncodingType()==PasswordEncodingType.ENCRYPT)==false)
       throw new RuntimeException("Invalid configuration, cannot decode passwords");       
        try {
            digest = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No MD5 algorithm available!");
        } 
    }

    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException,
            DataAccessException {
        
        if (GeoServerRootAuthenticationProvider.ROOT_USERNAME.equals(username))
            return prepareForRootUser ();
        
        GeoServerUser user = (GeoServerUser) service.loadUserByUsername(username);            
        return prepareForUser(user);
    }

    UserDetails prepareForUser (GeoServerUser user) {
        char[] pw = null;
        try {
            pw = enc.decodeToCharArray(user.getPassword());
            String a1 = encodePasswordInA1Format(user.getUsername(), 
                    GeoServerSecurityManager.REALM, pw);
            return new UserDetailsPasswordWrapper(user, a1);
        } finally {
            manager.disposePassword(pw);
        }        
    }
    
    UserDetails prepareForRootUser () {
        
        char[] mpw = null;
        try {
            mpw= manager.getMasterPassword();
            String a1 = encodePasswordInA1Format(GeoServerRootAuthenticationProvider.ROOT_USERNAME, 
                    GeoServerSecurityManager.REALM, mpw);
            
            return new UserDetailsPasswordWrapper(
                    GeoServerUser.createRoot(), a1);
        }
        finally {
            if (mpw!=null)
                manager.disposePassword(mpw);
        }
    }
    
    String encodePasswordInA1Format(String username, String realm, char[] password) {
        char[] array = null;
        try {
            char[] usernameArray = username.toCharArray();
            char[] realmArray = realm.toCharArray();
            
            array = new char[usernameArray.length+realmArray.length+password.length+2];
            int pos=0;
            
            System.arraycopy(usernameArray, 0, array, pos, usernameArray.length);
            pos+=usernameArray.length;
            
            System.arraycopy(delimArray, 0, array, pos, 1);
            pos++;
    
            System.arraycopy(realmArray, 0, array, pos, realmArray.length);
            pos+=realmArray.length;
            
            System.arraycopy(delimArray, 0, array, pos, 1);
            pos++;
    
            System.arraycopy(password, 0, array, pos, password.length);
            
            return new String(Hex.encode(digest.digest(SecurityUtils.toBytes(array, charSet))));
        } finally {
            if (array!=null)
                manager.disposePassword(array);
        }                        
    }
    
}
