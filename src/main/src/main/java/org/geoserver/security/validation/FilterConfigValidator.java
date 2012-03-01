/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */


package org.geoserver.security.validation;

import java.io.IOException;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.BasicAuthenticationFilterConfig;
import org.geoserver.security.config.DigestAuthenticationFilterConfig;
import org.geoserver.security.config.GeoServerRoleFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;

public class FilterConfigValidator extends SecurityConfigValidator {

    public FilterConfigValidator(GeoServerSecurityManager securityManager) {
        super(securityManager);
        
    }
    
    /**
     * Helper method for creating a proper
     * {@link FilterConfigException} object
     */
    protected FilterConfigException createFilterException (String errorid, Object ...args) {
        return new FilterConfigException(errorid,args);
    }

    @Override
    public void validateAddFilter(SecurityNamedServiceConfig config) throws SecurityConfigException {
        super.validateAddFilter(config);
    }

    @Override
    public void validateModifiedFilter(SecurityNamedServiceConfig config,
            SecurityNamedServiceConfig oldConfig) throws SecurityConfigException {
        super.validateModifiedFilter(config, oldConfig);
    }

    @Override
    public void validateRemoveFilter(SecurityNamedServiceConfig config)
            throws SecurityConfigException {
        super.validateRemoveFilter(config);
    }
    
    public void validateFilterConfig(SecurityNamedServiceConfig config) throws FilterConfigException {
        if (config instanceof BasicAuthenticationFilterConfig)
            validateFilterConfig((BasicAuthenticationFilterConfig)config);
        if (config instanceof DigestAuthenticationFilterConfig)
            validateFilterConfig((DigestAuthenticationFilterConfig)config);
        if (config instanceof GeoServerRoleFilterConfig)
            validateFilterConfig((GeoServerRoleFilterConfig)config);        
    }
    
    public void validateFilterConfig(BasicAuthenticationFilterConfig config) throws FilterConfigException {
        // TODO, check rememberme        
    }
    public void validateFilterConfig(DigestAuthenticationFilterConfig config) throws FilterConfigException {
        if (config.getUserGroupServiceName().isEmpty())
            throw createFilterException(FilterConfigException.USER_GROUP_SERVICE_NEEDED);

        try {
            if (manager.listUserGroupServices().contains(config.getUserGroupServiceName())==false)
                throw createFilterException(FilterConfigException.UNKNOWN_USER_GROUP_SERVICE,
                        config.getUserGroupServiceName());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        if (config.getNonceValiditySeconds() < 0)
            throw createFilterException(FilterConfigException.INVALID_SECONDS);
    }
    
    public void validateFilterConfig(GeoServerRoleFilterConfig config) throws FilterConfigException {
        if (isNotEmpty(config.getHttpResponseHeaderAttrForIncludedRoles())==false) {
                throw 
                  createFilterException(FilterConfigException.HEADER_ATTRIBUTE_NAME_REQUIRED);
        }
        if (isNotEmpty(config.getRoleConverterName())) {
            if (GeoServerExtensions.bean(config.getRoleConverterName())==null)
                throw createFilterException(FilterConfigException.UNKNOWN_ROLE_CONVERTER,
                        config.getRoleConverterName());
        }
    }




}
