/* Copyright (c) 2001 - 2008 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */


package org.geoserver.security.validation;

import java.io.IOException;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.BasicAuthenticationFilterConfig;
import org.geoserver.security.config.CasAuthenticationFilterConfig;
import org.geoserver.security.config.DigestAuthenticationFilterConfig;
import org.geoserver.security.config.ExceptionTranslationFilterConfig;
import org.geoserver.security.config.GeoServerRoleFilterConfig;
import org.geoserver.security.config.J2eeAuthenticationFilterConfig;
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.config.UsernamePasswordAuthenticationFilterConfig;
import org.geoserver.security.config.X509CertificateAuthenticationFilterConfig;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;

/**
 * Validator for filter configuration objects
 * 
 * 
 * @author mcr
 *
 */
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
        validateFilterConfig(config);
    }

    @Override
    public void validateModifiedFilter(SecurityNamedServiceConfig config,
            SecurityNamedServiceConfig oldConfig) throws SecurityConfigException {
        super.validateModifiedFilter(config, oldConfig);
        validateFilterConfig(config);
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
        if (config instanceof X509CertificateAuthenticationFilterConfig)
            validateFilterConfig((X509CertificateAuthenticationFilterConfig)config);
        if (config instanceof UsernamePasswordAuthenticationFilterConfig)
            validateFilterConfig((UsernamePasswordAuthenticationFilterConfig)config);
        if (config instanceof RequestHeaderAuthenticationFilterConfig)
            validateFilterConfig((RequestHeaderAuthenticationFilterConfig)config);
        if (config instanceof J2eeAuthenticationFilterConfig)
            validateFilterConfig((J2eeAuthenticationFilterConfig)config);
        if (config instanceof ExceptionTranslationFilterConfig)
            validateFilterConfig((ExceptionTranslationFilterConfig)config);
        if (config instanceof CasAuthenticationFilterConfig)
            validateFilterConfig((CasAuthenticationFilterConfig)config);

        
        // TODO, check rememberme        

    }
    
    protected void checkExistingUGService (String ugServiceName) throws FilterConfigException {
        if (isNotEmpty(ugServiceName)==false)
            throw createFilterException(FilterConfigException.USER_GROUP_SERVICE_NEEDED);
        try {
            if (manager.listUserGroupServices().contains(ugServiceName)==false)
                throw createFilterException(FilterConfigException.UNKNOWN_USER_GROUP_SERVICE,
                        ugServiceName);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }        
    }
    
    protected void checkExistingRoleService (String roleServiceName) throws FilterConfigException {
        if (isNotEmpty(roleServiceName)==false)
            throw createFilterException(FilterConfigException.ROLE_SERVICE_NEEDED);
        try {
            if (manager.listRoleServices().contains(roleServiceName)==false)
                throw createFilterException(FilterConfigException.UNKNOWN_ROLE_SERVICE,
                        roleServiceName);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }        
    }

    
    public void validateFilterConfig(BasicAuthenticationFilterConfig config) throws FilterConfigException {
        // Nothing to validate at the moment
    }
    public void validateFilterConfig(DigestAuthenticationFilterConfig config) throws FilterConfigException {
        checkExistingUGService(config.getUserGroupServiceName());
        if (config.getNonceValiditySeconds() < 0)
            throw createFilterException(FilterConfigException.INVALID_SECONDS);
    }
    
    public void validateFilterConfig(GeoServerRoleFilterConfig config) throws FilterConfigException {
        if (isNotEmpty(config.getHttpResponseHeaderAttrForIncludedRoles())==false) {
                throw 
                  createFilterException(FilterConfigException.HEADER_ATTRIBUTE_NAME_REQUIRED);
        }
        if (isNotEmpty(config.getRoleConverterName())) {
            try {
                GeoServerExtensions.bean(config.getRoleConverterName());
            } catch (NoSuchBeanDefinitionException ex) {
                throw createFilterException(FilterConfigException.UNKNOWN_ROLE_CONVERTER,
                        config.getRoleConverterName());
            }
        }
    }

    public void validateFilterConfig(X509CertificateAuthenticationFilterConfig config) throws FilterConfigException {
        if (config.getRoleSource()==null)
            throw createFilterException(FilterConfigException.ROLE_SOURCE_NEEDED);
        if (config.getRoleSource().
                equals(X509CertificateAuthenticationFilterConfig.RoleSource.RoleService))
                checkExistingRoleService(config.getRoleServiceName());
        if (config.getRoleSource().
                equals(X509CertificateAuthenticationFilterConfig.RoleSource.UGService))
                checkExistingUGService(config.getUserGroupServiceName());

    }

    public void validateFilterConfig(UsernamePasswordAuthenticationFilterConfig config) throws FilterConfigException {
        if (isNotEmpty(config.getUsernameParameterName())==false) {
            throw createFilterException(FilterConfigException.USER_PARAMETER_NAME_NEEDED);
        }
        if (isNotEmpty(config.getPasswordParameterName())==false) {
            throw createFilterException(FilterConfigException.PASSWORD_PARAMETER_NAME_NEEDED);
        }
    }

    public void validateFilterConfig(RequestHeaderAuthenticationFilterConfig config) throws FilterConfigException {
        
        if (isNotEmpty(config.getPrincipalHeaderAttribute())==false)
            throw createFilterException(FilterConfigException.PRINCIPAL_HEADER_ATTRIBUTE_NEEDED);
        
        if (config.getRoleSource()==null)
            throw createFilterException(FilterConfigException.ROLE_SOURCE_NEEDED);
        
        if (config.getRoleSource().
                equals(RequestHeaderAuthenticationFilterConfig.RoleSource.RoleService))
            checkExistingRoleService(config.getRoleServiceName());

        if (config.getRoleSource().
                equals(RequestHeaderAuthenticationFilterConfig.RoleSource.UGService))
                checkExistingUGService(config.getUserGroupServiceName());
        
        if (config.getRoleSource().
                equals(RequestHeaderAuthenticationFilterConfig.RoleSource.HEADER)) {
            if (isNotEmpty(config.getRolesHeaderAttribute())==false)
                throw createFilterException(FilterConfigException.ROLES_HEADER_ATTRIBUTE_NEEDED);
            if (isNotEmpty(config.getRoleConverterName())) {
                try {
                    GeoServerExtensions.bean(config.getRoleConverterName());
                } catch (NoSuchBeanDefinitionException ex) {
                    throw createFilterException(FilterConfigException.UNKNOWN_ROLE_CONVERTER,
                            config.getRoleConverterName());
                }
            }

        }

    }
    
    public void validateFilterConfig(J2eeAuthenticationFilterConfig config) throws FilterConfigException {
        checkExistingRoleService(config.getRoleServiceName());
    }
    
    public void validateFilterConfig(ExceptionTranslationFilterConfig config) throws FilterConfigException {
        
        if (isNotEmpty(config.getAccessDeniedErrorPage())==false) {
            throw createFilterException(FilterConfigException.ACCESS_DENIED_PAGE_NEEDED);
        }
        if (isNotEmpty(config.getAuthenticationEntryPointName())) {
            try {
                GeoServerExtensions.bean(config.getAuthenticationEntryPointName());
            } catch (NoSuchBeanDefinitionException ex) {
                throw createFilterException(FilterConfigException.INVALID_ENTRY_POINT,
                        config.getAuthenticationEntryPointName());
            }
        }
    }

    public void validateFilterConfig(CasAuthenticationFilterConfig config) throws FilterConfigException {
        // TODO
    }


}
