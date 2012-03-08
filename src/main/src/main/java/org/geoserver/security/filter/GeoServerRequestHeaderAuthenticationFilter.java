/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.logging.Level;

import javax.servlet.http.HttpServletRequest;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerRoleConverter;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig;
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig.RoleSource;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.impl.RoleCalculator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * J2EE Authentication Filter
 * 
 * @author mcr
 *
 */
public class GeoServerRequestHeaderAuthenticationFilter extends GeoServerAbstractPreAuthenticationFilter {
    
    private RoleSource roleSource;
    private String principalHeaderAttribute;
    private String rolesHeaderAttribute;
    private String userGroupServiceName;
    private String roleConverterName;
    private String roleServiceName;
    private GeoServerRoleConverter converter;

    public RoleSource getRoleSource() {
        return roleSource;
    }

    public void setRoleSource(RoleSource roleSource) {
        this.roleSource = roleSource;
    }

    public String getPrincipalHeaderAttribute() {
        return principalHeaderAttribute;
    }

    public void setPrincipalHeaderAttribute(String principalHeaderAttribute) {
        this.principalHeaderAttribute = principalHeaderAttribute;
    }

    public String getRolesHeaderAttribute() {
        return rolesHeaderAttribute;
    }

    public void setRolesHeaderAttribute(String rolesHeaderAttribute) {
        this.rolesHeaderAttribute = rolesHeaderAttribute;
    }

    public String getUserGroupServiceName() {
        return userGroupServiceName;
    }

    public void setUserGroupServiceName(String userGroupServiceName) {
        this.userGroupServiceName = userGroupServiceName;
    }

    public String getRoleConverterName() {
        return roleConverterName;
    }

    public void setRoleConverterName(String roleConverterName) {
        this.roleConverterName = roleConverterName;
    }


    
    public String getRoleServiceName() {
        return roleServiceName;
    }

    public void setRoleServiceName(String roleServiceName) {
        this.roleServiceName = roleServiceName;
    }

    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config) throws IOException {
        super.initializeFromConfig(config);
                        
        RequestHeaderAuthenticationFilterConfig authConfig = 
                (RequestHeaderAuthenticationFilterConfig) config;

        roleSource=authConfig.getRoleSource();
        principalHeaderAttribute=authConfig.getPrincipalHeaderAttribute();
        rolesHeaderAttribute=authConfig.getRolesHeaderAttribute();
        userGroupServiceName=authConfig.getUserGroupServiceName();
        roleConverterName=authConfig.getRoleConverterName();
        roleServiceName=authConfig.getRoleServiceName();     
        
        // TODO, Justin, is this ok ?
        if (RoleSource.HEADER.equals(roleSource)) {
            String converterName = authConfig.getRoleConverterName();        
            if (converterName==null || converterName.length()==0)
                setConverter(GeoServerExtensions.bean(GeoServerRoleConverter.class));
            else
                setConverter((GeoServerRoleConverter) 
                    GeoServerExtensions.bean(converterName));
        }        
    }

    @Override
    protected String getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String principal =request.getHeader(getPrincipalHeaderAttribute());
        if (principal!=null && principal.trim().length()==0)
            principal=null;
        
        try {
            if (principal!=null && RoleSource.UGService.equals(getRoleSource())) {
                GeoServerUserGroupService service = getSecurityManager().loadUserGroupService(getUserGroupServiceName());
                GeoServerUser u = service.getUserByUsername(principal);
                if (u!=null && u.isEnabled()==false)
                    principal=null;            
            }
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        return principal;    
    }

    @Override
    protected Collection<GeoServerRole> getRoles(HttpServletRequest request, String principal) throws IOException{

        if (RoleSource.RoleService.equals(getRoleSource())) 
            return getRolesFromRoleService(request, principal);
        if (RoleSource.UGService.equals(getRoleSource())) 
            return getRolesFromUserGroupService(request, principal);
        if (RoleSource.HEADER.equals(getRoleSource())) 
            return getRolesFromHttpAttribute(request, principal);
        
        throw new RuntimeException("Never should reach this point");

    }
    
    /**
     * Calculates roles from a {@link GeoServerRoleService}
     * The default service is {@link GeoServerSecurityManager#getActiveRoleService()}
     * 
     * The result contains all inherited roles, but no personalized roles
     * 
     * @param request
     * @param principal
     * @return
     * @throws IOException
     */
    protected Collection<GeoServerRole> getRolesFromRoleService(HttpServletRequest request, String principal) throws IOException{
        Collection<GeoServerRole> roles = new ArrayList<GeoServerRole>();
        boolean useActiveService = getRoleServiceName()==null || 
                getRoleServiceName().trim().length()==0;
      
        GeoServerRoleService service = useActiveService ?
              getSecurityManager().getActiveRoleService() :
              getSecurityManager().loadRoleService(getRoleServiceName());

        roles.addAll(service.getRolesForUser(principal));       
      
        RoleCalculator calc = new RoleCalculator(service);
        calc.addInheritedRoles(roles);
        return roles;        
    }
    
    /**
     * Calculates roles using a {@link GeoServerUserGroupService}
     * if the principal is not found, an empty collection is returned
     * 
     * @param request
     * @param principal
     * @return
     * @throws IOException
     */
    protected Collection<GeoServerRole> getRolesFromUserGroupService(HttpServletRequest request, String principal) throws IOException{
        Collection<GeoServerRole> roles = new ArrayList<GeoServerRole>();
        
        GeoServerUserGroupService service = getSecurityManager().loadUserGroupService(getUserGroupServiceName());
        UserDetails details=null;
        try {
             details = service.loadUserByUsername(principal);
        } catch (UsernameNotFoundException ex) {
            LOGGER.log(Level.WARNING,"User "+ principal + " not found in " + getUserGroupServiceName());
        }
        
        if (details!=null) {
            for (GrantedAuthority auth : details.getAuthorities())
                roles.add((GeoServerRole)auth);
        }
        return roles;        
    }
    
    /**
     * Calculates roles using the String found in the http header attribute
     * if no role string is found, anempty collection is returned
     * 
     * The result contains personalized roles
     * 
     * @param request
     * @param principal
     * @return
     * @throws IOException
     */
    protected Collection<GeoServerRole> getRolesFromHttpAttribute(HttpServletRequest request, String principal) throws IOException{
        Collection<GeoServerRole> roles = new ArrayList<GeoServerRole>();

        String rolesString =request.getHeader(getRolesHeaderAttribute());
        if (rolesString ==null || rolesString.trim().length()==0) {
            LOGGER.log(Level.WARNING,"No roles in header attribute: " + getRolesHeaderAttribute());
            return roles;
        }

        roles.addAll(getConverter().convertRolesFromString(rolesString, principal));
        return roles;        
    }



    
    public GeoServerRoleConverter getConverter() {
        return converter;
    }

    public void setConverter(GeoServerRoleConverter converter) {
        this.converter = converter;
    }

}
