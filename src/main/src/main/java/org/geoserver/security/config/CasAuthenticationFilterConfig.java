/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.config;


/**
 * Configuration for cas authentication
 * 
 * 
 * @author mcr
 *
 */
public class CasAuthenticationFilterConfig extends NamedFilterConfig {

    private static final long serialVersionUID = 1L;
    
    private String userGroupServiceName;
     
    /**
     * The geoserver url where the case server sends credential information
     * 
     * example:
     * http://localhost:8080/geoserver/j_spring_cas_security_check
     */
    private String service;
    
    
    /**
     * if true, no single sign on possible
     */
    private boolean sendRenew;
    
    /**
     * Login url of the central cas server
     * 
     * example:
     * https://localhost:9443/cas/login"
     */
    private String loginUrl;
    
    
    
    /**
     * Url where to validate the ticket
     * 
     * example
     * "https://localhost:9443/cas" 
     */
    private String ticketValidatorUrl;



    public String getService() {
        return service;
    }



    public void setService(String service) {
        this.service = service;
    }



    public boolean isSendRenew() {
        return sendRenew;
    }



    public void setSendRenew(boolean sendRenew) {
        this.sendRenew = sendRenew;
    }



    public String getLoginUrl() {
        return loginUrl;
    }



    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }



    public String getTicketValidatorUrl() {
        return ticketValidatorUrl;
    }



    public void setTicketValidatorUrl(String ticketValidatorUrl) {
        this.ticketValidatorUrl = ticketValidatorUrl;
    }



    public String getUserGroupServiceName() {
        return userGroupServiceName;
    }



    public void setUserGroupServiceName(String userGroupServiceName) {
        this.userGroupServiceName = userGroupServiceName;
    }
    
        
}
