/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.validation;

import org.geoserver.security.impl.GeoServerRole;

/**
 * Exception used for validation errors concerning {@link GeoServerRole}
 * 
 * @author christian
 */
public class RoleServiceException extends AbstractSecurityException {
    private static final long serialVersionUID = 1L;

    public static final String NAME_REQUIRED = "NAME_REQUIRED";
    //return MessageFormat.format("Role name is mandatory",args);
    
    @Deprecated
    public static final String ROLE_ERR_01 = NAME_REQUIRED;
    
    public static final String NOT_FOUND = "NOT_FOUND";
    //return MessageFormat.format("Role {0} does not exist",args);
    
    @Deprecated
    public static final String ROLE_ERR_02 = NOT_FOUND;
    
    public static final String ALREADY_EXISTS = "ALREADY_EXIST";
    //return MessageFormat.format("Role {0} already exists",args);

    @Deprecated
    public static final String ROLE_ERR_03 = ALREADY_EXISTS;
    
    public static final String USERNAME_REQUIRED = "USERNAME_REQUIRED";
    //return MessageFormat.format("User name is mandatory",args);
    
    @Deprecated
    public static final String ROLE_ERR_04 = USERNAME_REQUIRED;

    public static final String GROUPNAME_REQUIRED = "USERNAME_REQUIRED";
    //return MessageFormat.format("Group name is mandatory",args);
    
    @Deprecated
    public static final String ROLE_ERR_05 = GROUPNAME_REQUIRED;
    
    public static final String USERNAME_NOT_FOUND_$1 = "USERNAME_NOT_FOUND";
    //return MessageFormat.format("User name {0} not found",args);
    
    @Deprecated
    public static final String ROLE_ERR_06 = USERNAME_NOT_FOUND_$1;

    public static final String GROUPNAME_NOT_FOUND_$1 = "GROUPNAME_NOT_FOUND";
    //return MessageFormat.format("Group name {0} not found",args);
    
    @Deprecated
    public static final String ROLE_ERR_07 = GROUPNAME_NOT_FOUND_$1;
    
    public static final String ADMIN_ROLE_NOT_REMOVABLE_$1 = "ADMIN_ROLE_NOT_REMOVABLE";
    //return MessageFormat.format("Administrator role {0} is not removable",args);

    @Deprecated
    public static final String ROLE_ERR_08 = ADMIN_ROLE_NOT_REMOVABLE_$1;

    public static final String ROLE_IN_USE_$2 = "ROLE_IN_USE";
    //return MessageFormat.format("The role {0} is used by the following rules: {1}",args);

    @Deprecated
    public static final String ROLE_ERR_09 = ROLE_IN_USE_$2;

    public RoleServiceException(String errorId, String message, Object[] args) {
        super(errorId, message, args);
    }
    
    public RoleServiceException(String errorId, Object[] args) {
        super(errorId, args);
    }
}
