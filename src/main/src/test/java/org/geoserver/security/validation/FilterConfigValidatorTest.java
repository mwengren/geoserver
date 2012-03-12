package org.geoserver.security.validation;

import java.util.logging.Logger;

import org.geoserver.security.GeoServerSecurityTestSupport;
import org.geoserver.security.config.DigestAuthenticationFilterConfig;
import org.geoserver.security.config.ExceptionTranslationFilterConfig;
import org.geoserver.security.config.GeoServerRoleFilterConfig;
import org.geoserver.security.config.J2eeAuthenticationFilterConfig;
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig;
import org.geoserver.security.config.UsernamePasswordAuthenticationFilterConfig;
import org.geoserver.security.config.X509CertificateAuthenticationFilterConfig;
import org.geoserver.security.filter.GeoServerDigestAuthenticationFilter;
import org.geoserver.security.filter.GeoServerExceptionTranslationFilter;
import org.geoserver.security.filter.GeoServerJ2eeAuthenticationFilter;
import org.geoserver.security.filter.GeoServerRequestHeaderAuthenticationFilter;
import org.geoserver.security.filter.GeoServerRoleFilter;
import org.geoserver.security.filter.GeoServerUserNamePasswordAuthenticationFilter;
import org.geoserver.security.filter.GeoServerX509CertificateAuthenticationFilter;
import org.geoserver.security.xml.XMLRoleService;
import org.geoserver.security.xml.XMLUserGroupService;
import org.geotools.util.logging.Logging;

public class FilterConfigValidatorTest extends GeoServerSecurityTestSupport {

    
    static protected Logger LOGGER = Logging.getLogger("org.geoserver.security");
        
    public void testDigestConfigValidation() throws Exception{
        DigestAuthenticationFilterConfig config = new DigestAuthenticationFilterConfig();
        config.setClassName(GeoServerDigestAuthenticationFilter.class.getName());
        config.setName("testDigest");
        
        boolean failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.USER_GROUP_SERVICE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setUserGroupServiceName("blabla");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.UNKNOWN_USER_GROUP_SERVICE,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("blabla",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        
        config.setUserGroupServiceName(XMLUserGroupService.DEFAULT_NAME);
        config.setNonceValiditySeconds(-1);
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.INVALID_SECONDS,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            failed=true;
        }
        assertTrue(failed);

        config.setNonceValiditySeconds(100);
        getSecurityManager().saveFilter(config);

    }
    
    public void testRoleFilterConfigValidation() throws Exception{
       GeoServerRoleFilterConfig config = new GeoServerRoleFilterConfig();
        config.setClassName(GeoServerRoleFilter.class.getName());
        config.setName("testRoleFilter");
        
        boolean failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.HEADER_ATTRIBUTE_NAME_REQUIRED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setHttpResponseHeaderAttrForIncludedRoles("roles");
        config.setRoleConverterName("unknown");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.UNKNOWN_ROLE_CONVERTER,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("unknown",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        

        config.setRoleConverterName(null);
        getSecurityManager().saveFilter(config);

    }
    
    public void testX509FilterConfigValidation() throws Exception{
        X509CertificateAuthenticationFilterConfig config = new X509CertificateAuthenticationFilterConfig();
        config.setClassName(GeoServerX509CertificateAuthenticationFilter.class.getName());
        config.setName("testX509");

        boolean failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.ROLE_SOURCE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);

        
        config.setRoleSource(X509CertificateAuthenticationFilterConfig.RoleSource.UGService);
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.USER_GROUP_SERVICE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setUserGroupServiceName("blabla");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.UNKNOWN_USER_GROUP_SERVICE,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("blabla",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        
        config.setUserGroupServiceName(XMLUserGroupService.DEFAULT_NAME);
        getSecurityManager().saveFilter(config);
        
        config.setRoleSource(X509CertificateAuthenticationFilterConfig.RoleSource.RoleService);        
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.ROLE_SERVICE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setRoleServiceName("blabla");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.UNKNOWN_ROLE_SERVICE,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("blabla",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        
        config.setRoleServiceName(XMLRoleService.DEFAULT_NAME);
        getSecurityManager().saveFilter(config);

    }


    public void testUsernamePasswordFilterConfigValidation() throws Exception{
        UsernamePasswordAuthenticationFilterConfig config = 
                new UsernamePasswordAuthenticationFilterConfig();
        config.setClassName(GeoServerUserNamePasswordAuthenticationFilter.class.getName());
        config.setName("testUsernamePassword");
        
        boolean failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.USER_PARAMETER_NAME_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setUsernameParameterName("user");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.PASSWORD_PARAMETER_NAME_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());            
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        
        config.setPasswordParameterName("password");
        getSecurityManager().saveFilter(config);

    }

    public void testJ2eeFilterConfigValidation() throws Exception{
        J2eeAuthenticationFilterConfig config = new J2eeAuthenticationFilterConfig();
        config.setClassName(GeoServerJ2eeAuthenticationFilter.class.getName());
        config.setName("testJ2ee");
        
        boolean failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.ROLE_SERVICE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setRoleServiceName("blabla");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.UNKNOWN_ROLE_SERVICE,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("blabla",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        
        config.setRoleServiceName(XMLRoleService.DEFAULT_NAME);
        getSecurityManager().saveFilter(config);

    }
    
    public void testExceptionTranslationFilterConfigValidation() throws Exception{
        ExceptionTranslationFilterConfig config = new ExceptionTranslationFilterConfig();
        config.setClassName(GeoServerExceptionTranslationFilter.class.getName());
        config.setName("testEx");
        
        boolean failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.ACCESS_DENIED_PAGE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setAccessDeniedErrorPage("blabla");
        config.setAuthenticationEntryPointName("unknown");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.INVALID_ENTRY_POINT,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("unknown",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        config.setAuthenticationEntryPointName(null);        
        getSecurityManager().saveFilter(config);
    }

    public void testRequestHeaderFilterConfigValidation() throws Exception{
        RequestHeaderAuthenticationFilterConfig config = new RequestHeaderAuthenticationFilterConfig();
        config.setClassName(GeoServerRequestHeaderAuthenticationFilter.class.getName());
        config.setName("testRequestHeader");

        boolean failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.PRINCIPAL_HEADER_ATTRIBUTE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);

        config.setPrincipalHeaderAttribute("user");

        
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.ROLE_SOURCE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);

        
        config.setRoleSource(RequestHeaderAuthenticationFilterConfig.RoleSource.UGService);
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.USER_GROUP_SERVICE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setUserGroupServiceName("blabla");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.UNKNOWN_USER_GROUP_SERVICE,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("blabla",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        
        config.setUserGroupServiceName(XMLUserGroupService.DEFAULT_NAME);
        getSecurityManager().saveFilter(config);
        
        config.setRoleSource(RequestHeaderAuthenticationFilterConfig.RoleSource.RoleService);        
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.ROLE_SERVICE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        
        config.setRoleServiceName("blabla");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.UNKNOWN_ROLE_SERVICE,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("blabla",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        
        config.setRoleServiceName(XMLRoleService.DEFAULT_NAME);
        getSecurityManager().saveFilter(config);
        
        config.setRoleSource(RequestHeaderAuthenticationFilterConfig.RoleSource.HEADER);
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.ROLES_HEADER_ATTRIBUTE_NEEDED,ex.getId());
            assertEquals(0,ex.getArgs().length);
            LOGGER.info(ex.getMessage());
            
            failed=true;
        }
        assertTrue(failed);
        config.setRolesHeaderAttribute("roles");

        config.setRoleConverterName("unknown");
        failed = false;                                        
        try {
            getSecurityManager().saveFilter(config);
        } catch (FilterConfigException ex){
            assertEquals(FilterConfigException.UNKNOWN_ROLE_CONVERTER,ex.getId());
            assertEquals(1,ex.getArgs().length);
            assertEquals("unknown",ex.getArgs()[0]);
            LOGGER.info(ex.getMessage());            
            failed=true;
        }
        assertTrue(failed);
        
        config.setRoleConverterName(null);
        getSecurityManager().saveFilter(config);

    }


}
