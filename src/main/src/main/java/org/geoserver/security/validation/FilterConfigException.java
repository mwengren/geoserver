/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.validation;

/**
 * Exception for filter configurations
 * 
 * @author mcr
 *
 */
public class FilterConfigException extends SecurityConfigException {

    private static final long serialVersionUID = 1L;

    public FilterConfigException(String errorId, Object... args) {
        super(errorId, args);
        
    }

    public FilterConfigException(String errorId, String message, Object... args) {
        super(errorId, message, args);
        
    }
    
    public static final String HEADER_ATTRIBUTE_NAME_REQUIRED="HEADER_ATTRIBUTE_NAME_REQUIRED";
    public static final String UNKNOWN_ROLE_CONVERTER="UNKNOWN_ROLE_CONVERTER";

    public static final String USER_GROUP_SERVICE_NEEDED="USER_GROUP_SERVICE_NEEDED";
    public static final String UNKNOWN_USER_GROUP_SERVICE="UNKNOWN_USER_GROUP_SERVICE";
    public static final String INVALID_SECONDS="INVALID_SECONDS";

}
