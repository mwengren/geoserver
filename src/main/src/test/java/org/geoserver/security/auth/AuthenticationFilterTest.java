/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */


package org.geoserver.security.auth;

import java.security.Principal;
import java.text.MessageFormat;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.geoserver.security.GeoServerAuthenticationProvider;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerRoleStore;
import org.geoserver.security.GeoServerSecurityFilterChain;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.GeoServerUserGroupStore;
import org.geoserver.security.config.BasicAuthenticationFilterConfig;
import org.geoserver.security.config.DigestAuthenticationFilterConfig;
import org.geoserver.security.config.ExceptionTranslationFilterConfig;
import org.geoserver.security.config.J2eeAuthenticationFilterConfig;
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig;
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig.RoleSource;
import org.geoserver.security.config.SecurityManagerConfig;
import org.geoserver.security.filter.GeoServerBasicAuthenticationFilter;
import org.geoserver.security.filter.GeoServerDigestAuthenticationFilter;
import org.geoserver.security.filter.GeoServerExceptionTranslationFilter;
import org.geoserver.security.filter.GeoServerJ2eeAuthenticationFilter;
import org.geoserver.security.filter.GeoServerRequestHeaderAuthenticationFilter;
import org.geoserver.security.impl.DigestAuthUtils;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geotools.data.Base64;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import com.mockrunner.mock.web.MockFilterChain;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;

public class AuthenticationFilterTest extends AbstractAuthenticationProviderTest {
    
    public final static String testFilterName = "basicAuthTestFilter";
    public final static String testFilterName2 = "digestAuthTestFilter";
    public final static String testFilterName3 = "j2eeAuthTestFilter";
    public final static String testFilterName4 = "requestHeaderTestFilter";
    public final static String testFilterName5 = "basicAuthTestFilterWithRemeberMe";

    public final static String accessDeniedFilter = "accessDeniedFilter";
    public final static String digestEntryPointFilter = "digestEntryPointFilter";
    public final static String testProviderName = "basicAuthTestProvider";
    public final static String testUserName = "user1";
    public final static String testPassword = "pw1";
    public final static String rootRole = "RootRole";
    public final static String derivedRole = "DerivedRole";
    public final static String pattern = "/foo/**";
    
    
    @Override
    protected void setUpInternal() throws Exception {
        super.setUpInternal();
        createServices();
    }
    
    protected void createServices() throws Exception{
        
        GeoServerRoleService rservice = createRoleService("rs1");
        GeoServerRoleStore rstore = rservice.createStore();
        GeoServerRole root, derived;
        rstore.addRole(root=rstore.createRoleObject(rootRole));
        rstore.addRole(derived=rstore.createRoleObject(derivedRole));
        rstore.setParentRole(derived, root);
        rstore.associateRoleToUser(derived, testUserName);
        rstore.store();
        
        SecurityManagerConfig mconfig = getSecurityManager().loadSecurityConfig();
        mconfig.setRoleServiceName("rs1");
        getSecurityManager().saveSecurityConfig(mconfig);
        
        GeoServerUserGroupService ugservice = createUserGroupService("ug1");
        GeoServerUserGroupStore ugstore = ugservice.createStore();
        GeoServerUser u1 = ugstore.createUserObject(testUserName, testPassword, true);
        ugstore.addUser(u1);
        GeoServerUser u2 = ugstore.createUserObject("abc@xyz.com", "abc", true);
        ugstore.addUser(u2);

        ugstore.store();
        
        GeoServerAuthenticationProvider prov = createAuthProvider(testProviderName, ugservice.getName());
        prepareAuthProviders(prov.getName());        
        
        ExceptionTranslationFilterConfig exConfig = new ExceptionTranslationFilterConfig();
        exConfig.setClassName(GeoServerExceptionTranslationFilter.class.getName());
        exConfig.setName(accessDeniedFilter);
        exConfig.setAuthenticationEntryPointName("accessDeniedEntryPoint");
        getSecurityManager().saveFilter(exConfig);
        
        exConfig = new ExceptionTranslationFilterConfig();
        exConfig.setClassName(GeoServerExceptionTranslationFilter.class.getName());
        exConfig.setName(digestEntryPointFilter);
        exConfig.setAuthenticationEntryPointName("digestProcessingFilterEntryPoint");
        getSecurityManager().saveFilter(exConfig);

    }
    
    protected void insertAnonymousFilter(String beforName) throws Exception{
        SecurityManagerConfig mconfig = getSecurityManager().loadSecurityConfig();
        mconfig.getFilterChain().insertBefore(pattern,GeoServerSecurityFilterChain.ANONYMOUS_FILTER,beforName);
        getSecurityManager().saveSecurityConfig(mconfig);        
    }
    
    protected void removeAnonymousFilter() throws Exception{
        SecurityManagerConfig mconfig = getSecurityManager().loadSecurityConfig();
        mconfig.getFilterChain().getFilterMap().get(pattern).remove(GeoServerSecurityFilterChain.ANONYMOUS_FILTER);
        getSecurityManager().saveSecurityConfig(mconfig);        
    }

    
    public void testBasicAuth() throws Exception{
        
                
        BasicAuthenticationFilterConfig config = new BasicAuthenticationFilterConfig();
        config.setClassName(GeoServerBasicAuthenticationFilter.class.getName());
        config.setUseRememberMe(false);
        config.setName(testFilterName);
        
        getSecurityManager().saveFilter(config);
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,    
            testFilterName,
            GeoServerSecurityFilterChain.EXCEPTION_TRANSLATION_OWS_FILTER,
            GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);


        SecurityContextHolder.getContext().setAuthentication(null);
        
        // Test entry point                
        MockHttpServletRequest request= createRequest("/foo/bar");
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();        
        
        
        getProxy().doFilter(request, response, chain);
        String tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Basic") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        
        // check success
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        

        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((testUserName+":"+testPassword).getBytes())));
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        Authentication auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, ((UserDetails) auth.getPrincipal()).getUsername());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));
        
        // check wrong password
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();

        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((testUserName+":wrongpass").getBytes())));
        getProxy().doFilter(request, response, chain);
        tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Basic") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        // check unknown user
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();

        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes(("unknwon:"+testPassword).getBytes())));
        getProxy().doFilter(request, response, chain);
        tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Basic") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // check root user
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
        
        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((GeoServerUser.ROOT_USERNAME+":geoserver").getBytes())));
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        //checkForAuthenticatedRole(auth);
        assertEquals(GeoServerUser.ROOT_USERNAME, auth.getPrincipal());
        assertTrue(auth.getAuthorities().size()==1);
        assertTrue(auth.getAuthorities().contains(GeoServerRole.ADMIN_ROLE));
        
        // check root user with wrong password
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
        
        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((GeoServerUser.ROOT_USERNAME+":geoserver1").getBytes())));
        getProxy().doFilter(request, response, chain);
        tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Basic") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        
        // check disabled user
        updateUser("ug1", testUserName, false);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        

        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((testUserName+":"+testPassword).getBytes())));
        getProxy().doFilter(request, response, chain);
        tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Basic") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        updateUser("ug1", testUserName, true);
        
        // Test anonymous
        insertAnonymousFilter(GeoServerSecurityFilterChain.EXCEPTION_TRANSLATION_OWS_FILTER);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();                        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        // Anonymous context is not stored in http session, no further testing
        removeAnonymousFilter();

    }
    
    public void testJ2eeProxy() throws Exception{

        J2eeAuthenticationFilterConfig config = new J2eeAuthenticationFilterConfig();        
        config.setClassName(GeoServerJ2eeAuthenticationFilter.class.getName());        
        config.setName(testFilterName3);
        config.setRoleServiceName("rs1");        
        getSecurityManager().saveFilter(config);
        
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,    
            testFilterName3,
            accessDeniedFilter,
            GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);


        SecurityContextHolder.getContext().setAuthentication(null);
        
        // Test entry point                
        MockHttpServletRequest request= createRequest("/foo/bar");
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();                
        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getErrorCode());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());


        // test preauthenticated with dedicated role service        
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();                
        request.setUserPrincipal(new Principal() {            
            @Override
            public String getName() {
                return testUserName;
            }
        });
        request.setUserInRole(derivedRole,true);
        request.setUserInRole(rootRole,false);
        getProxy().doFilter(request, response, chain);
        
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        Authentication auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, auth.getPrincipal());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));
        
        // test root                
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();                
        request.setUserPrincipal(new Principal() {            
            @Override
            public String getName() {
                return GeoServerUser.ROOT_USERNAME;
            }
        });
        getProxy().doFilter(request, response, chain);
        
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        //checkForAuthenticatedRole(auth);
        assertEquals(GeoServerUser.ROOT_USERNAME, auth.getPrincipal());
        assertTrue(auth.getAuthorities().size()==1);
        assertTrue(auth.getAuthorities().contains(GeoServerRole.ADMIN_ROLE));

        config.setRoleServiceName(null);
        getSecurityManager().saveFilter(config);
        
        // test preauthenticated with active role service                
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();                
        request.setUserPrincipal(new Principal() {            
            @Override
            public String getName() {
                return testUserName;
            }
        });
        request.setUserInRole(derivedRole,true);
        request.setUserInRole(rootRole,false);
        getProxy().doFilter(request, response, chain);
        
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        auth=ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, auth.getPrincipal());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));
        
        // Test anonymous
        insertAnonymousFilter(accessDeniedFilter);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();                        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        // Anonymous context is not stored in http session, no further testing
        removeAnonymousFilter();

                
    }
    
    public void testRequestHeaderProxy() throws Exception{

        RequestHeaderAuthenticationFilterConfig config = 
                new RequestHeaderAuthenticationFilterConfig();        
        config.setClassName(GeoServerRequestHeaderAuthenticationFilter.class.getName());        
        config.setName(testFilterName4);
        config.setRoleServiceName("rs1");
        config.setPrincipalHeaderAttribute("principal");
        config.setRoleSource(RoleSource.RoleService);
        config.setUserGroupServiceName("ug1");
        config.setPrincipalHeaderAttribute("principal");
        config.setRolesHeaderAttribute("roles");;
        getSecurityManager().saveFilter(config);
        
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,    
            testFilterName4,
            accessDeniedFilter,
            GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);


        SecurityContextHolder.getContext().setAuthentication(null);
        
        // Test entry point                
        MockHttpServletRequest request= createRequest("/foo/bar");
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();                
        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getErrorCode());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        
        for (RoleSource rs : RoleSource.values()) {
            config.setRoleSource(rs);
            getSecurityManager().saveFilter(config);
            request= createRequest("/foo/bar");
            response= new MockHttpServletResponse();
            chain = new MockFilterChain();            
            request.setHeader("principal", testUserName);
            if (rs==RoleSource.HEADER) {
                request.setHeader("roles", derivedRole+";"+rootRole);
            }
            getProxy().doFilter(request, response, chain);            
            assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
            ctx = (SecurityContext)request.getSession(true).getAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
            assertNotNull(ctx);
            Authentication auth = ctx.getAuthentication();
            assertNotNull(auth);
            assertNull(SecurityContextHolder.getContext().getAuthentication());
            checkForAuthenticatedRole(auth);
            assertEquals(testUserName, auth.getPrincipal());
            assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
            assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));        
        }

        // unknown user
        for (RoleSource rs : RoleSource.values()) {
            config.setRoleSource(rs);
            getSecurityManager().saveFilter(config);

            config.setRoleSource(rs);
            request= createRequest("/foo/bar");
            response= new MockHttpServletResponse();
            chain = new MockFilterChain();            
            request.setHeader("principal", "unknwon");
            getProxy().doFilter(request, response, chain);            
            assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
            ctx = (SecurityContext)request.getSession(true).getAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
            assertNotNull(ctx);
            Authentication auth = ctx.getAuthentication();
            assertNotNull(auth);
            assertNull(SecurityContextHolder.getContext().getAuthentication());
            checkForAuthenticatedRole(auth);
            assertEquals("unknwon", auth.getPrincipal());
        }

        // test disabled user
        updateUser("ug1", testUserName, false);
        config.setRoleSource(RoleSource.UGService);
        getSecurityManager().saveFilter(config);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();            
        getProxy().doFilter(request, response, chain);            
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        // Test anonymous
        insertAnonymousFilter(accessDeniedFilter);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();                        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        // Anonymous context is not stored in http session, no further testing
        removeAnonymousFilter();

                
    }        


    protected String clientDigestString(String serverDigestString, String username, String password, String method) {
        String section212response = serverDigestString.substring(7);
        String[] headerEntries = DigestAuthUtils.splitIgnoringQuotes(section212response, ',');
        Map<String,String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");

        String realm = headerMap.get("realm");
        String qop= headerMap.get("qop");
        String nonce= headerMap.get("nonce");
        
        String uri="/foo/bar";
        String nc="00000001";
        String cnonce="0a4f113b";
        String  opaque="5ccc069c403ebaf9f0171e9517f40e41";
        
        String responseString = DigestAuthUtils.generateDigest(
                false, username, realm, password, method, 
                uri, qop, nonce, nc, cnonce);
        
        String template = "Digest username=\"{0}\",realm=\"{1}\"";
        template+=",nonce=\"{2}\",uri=\"{3}\"";
        template+=",qop=\"{4}\",nc=\"{5}\"";
        template+=",cnonce=\"{6}\",response=\"{7}\"";
        template+=",opaque=\"{8}\"";
                
        return MessageFormat.format(template, 
                username,realm,nonce,uri,qop,nc,cnonce,responseString,opaque);
        
    }
    
    public void testDigestAuth() throws Exception{

        DigestAuthenticationFilterConfig config = new DigestAuthenticationFilterConfig();
        config.setClassName(GeoServerDigestAuthenticationFilter.class.getName());
        config.setName(testFilterName2);
        config.setUserGroupServiceName("ug1");
        
        getSecurityManager().saveFilter(config);
        prepareFiterChain(pattern,
                GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,    
                testFilterName2,
                digestEntryPointFilter,
                GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);


        SecurityContextHolder.getContext().setAuthentication(null);
            
        // Test entry point                
        MockHttpServletRequest request= createRequest("/foo/bar");
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();                
            
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED,response.getErrorCode());
        String tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Digest") !=-1 );
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        
        // test successful login
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        

        String headerValue=clientDigestString(tmp, testUserName, testPassword, request.getMethod());
        request.addHeader("Authorization",  headerValue);
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        Authentication auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, ((UserDetails) auth.getPrincipal()).getUsername());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));
        
        
        // check wrong password
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();

        headerValue=clientDigestString(tmp, testUserName, "wrongpass", request.getMethod());
        request.addHeader("Authorization",  headerValue);        
        getProxy().doFilter(request, response, chain);
        tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Digest") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        // check unknown user
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();

        headerValue=clientDigestString(tmp, "unknown", testPassword, request.getMethod());
        request.addHeader("Authorization",  headerValue);        
        getProxy().doFilter(request, response, chain);
        tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Digest") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // check root user
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
        
        headerValue=clientDigestString(tmp, GeoServerUser.ROOT_USERNAME, "geoserver", request.getMethod());
        request.addHeader("Authorization",  headerValue);        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        //checkForAuthenticatedRole(auth);
        assertEquals(GeoServerUser.ROOT_USERNAME, ((UserDetails) auth.getPrincipal()).getUsername());
        assertTrue(auth.getAuthorities().size()==1);
        assertTrue(auth.getAuthorities().contains(GeoServerRole.ADMIN_ROLE));
        
        // check root user with wrong password
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
        
        headerValue=clientDigestString(tmp, GeoServerUser.ROOT_USERNAME, "geoserver1", request.getMethod());
        request.addHeader("Authorization",  headerValue);        
        getProxy().doFilter(request, response, chain);
        tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Digest") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());


        
        // check disabled user
        updateUser("ug1", testUserName, false);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        

        headerValue=clientDigestString(tmp, "unknown", testPassword, request.getMethod());
        request.addHeader("Authorization",  headerValue);        
        getProxy().doFilter(request, response, chain);
        tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
        assert(tmp.indexOf(GeoServerSecurityManager.REALM) !=-1 );
        assert(tmp.indexOf("Digest") !=-1 );
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());        
        updateUser("ug1", testUserName, true);        


        // Test anonymous
        insertAnonymousFilter(digestEntryPointFilter);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();                        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        // Anonymous context is not stored in http session, no further testing
        removeAnonymousFilter();
    }

    public void testBasicAuthWithRememberMe() throws Exception{
    
        BasicAuthenticationFilterConfig config = new BasicAuthenticationFilterConfig();
        config.setClassName(GeoServerBasicAuthenticationFilter.class.getName());
        config.setUseRememberMe(true);
        config.setName(testFilterName5);
        
        getSecurityManager().saveFilter(config);
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,    
            testFilterName5,
            GeoServerSecurityFilterChain.REMEMBER_ME_FILTER,
            GeoServerSecurityFilterChain.EXCEPTION_TRANSLATION_OWS_FILTER,
            GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);
    
    
        SecurityContextHolder.getContext().setAuthentication(null);
        
        // Test entry point                
        MockHttpServletRequest request= createRequest("/foo/bar");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();        
                
        getProxy().doFilter(request, response, chain);
        assertEquals(0, response.getCookies().size());
        String tmp = response.getHeader("WWW-Authenticate");
        assertNotNull(tmp);
    
        
        // check success
        request= createRequest("/foo/bar");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
    
                
        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes(("abc@xyz.com:abc").getBytes())));
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        Authentication auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(1,response.getCookies().size());
        Cookie cookie = (Cookie) response.getCookies().get(0);

        request= createRequest("/foo/bar");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        request.addCookie(cookie);
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals("abc@xyz.com", ((UserDetails) auth.getPrincipal()).getUsername());
//        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
//        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));

        // send cookie + auth header
        request= createRequest("/foo/bar");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        request.addCookie(cookie);
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes(("abc@xyz.com:abc").getBytes())));
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals("abc@xyz.com", ((UserDetails) auth.getPrincipal()).getUsername());

        // check no remember me for root user
        request= createRequest("/foo/bar");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
    
                
        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((GeoServerUser.ROOT_USERNAME+":geoserver").getBytes())));
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        //checkForAuthenticatedRole(auth);
        // no cookie for root user
        assertEquals(0,response.getCookies().size());
        
        // check disabled user
        updateUser("ug1", "abc@xyz.com", false);
        
        request= createRequest("/foo/bar");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        request.addCookie(cookie);
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getErrorCode());
        // check for cancel cookie
        assertEquals(1,response.getCookies().size());
        Cookie cancelCookie = (Cookie) response.getCookies().get(0);
        assertNull(cancelCookie.getValue());
        updateUser("ug1", "abc@xyz.com", true);

        
    }

}
