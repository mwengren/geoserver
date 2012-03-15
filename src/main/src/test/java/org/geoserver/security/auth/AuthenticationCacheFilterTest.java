/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */


package org.geoserver.security.auth;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.geoserver.security.GeoServerSecurityFilterChain;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.BasicAuthenticationFilterConfig;
import org.geoserver.security.config.DigestAuthenticationFilterConfig;
import org.geoserver.security.config.J2eeAuthenticationFilterConfig;
import org.geoserver.security.config.LogoutFilterConfig;
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig;
import org.geoserver.security.config.RequestHeaderAuthenticationFilterConfig.RoleSource;
import org.geoserver.security.config.UsernamePasswordAuthenticationFilterConfig;
import org.geoserver.security.config.X509CertificateAuthenticationFilterConfig;
import org.geoserver.security.filter.GeoServerBasicAuthenticationFilter;
import org.geoserver.security.filter.GeoServerCompositeFilter;
import org.geoserver.security.filter.GeoServerDigestAuthenticationFilter;
import org.geoserver.security.filter.GeoServerJ2eeAuthenticationFilter;
import org.geoserver.security.filter.GeoServerLogoutFilter;
import org.geoserver.security.filter.GeoServerRequestHeaderAuthenticationFilter;
import org.geoserver.security.filter.GeoServerUserNamePasswordAuthenticationFilter;
import org.geoserver.security.filter.GeoServerX509CertificateAuthenticationFilter;
import org.geoserver.security.impl.DigestAuthUtils;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geotools.data.Base64;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import com.mockrunner.mock.web.MockFilterChain;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;

public class AuthenticationCacheFilterTest extends AbstractAuthenticationProviderTest {
    
    public final static String testFilterName = "basicAuthTestFilter";
    public final static String testFilterName2 = "digestAuthTestFilter";
    public final static String testFilterName3 = "j2eeAuthTestFilter";
    public final static String testFilterName4 = "requestHeaderTestFilter";
    public final static String testFilterName5 = "basicAuthTestFilterWithRememberMe";
    public final static String testFilterName6 = "formLoginTestFilter";
    public final static String testFilterName7 = "formLoginTestFilterWithRememberMe";
    public final static String testFilterName8 = "x509TestFilter";
    public final static String testFilterName9 = "logoutTestFilter";


    @Override
    protected void setUpInternal() throws Exception {
        super.setUpInternal();
        AuthenticationCacheImpl.Singleton=new TestingAuthenticationCache();
    }


    TestingAuthenticationCache getCache() {
        return (TestingAuthenticationCache) AuthenticationCacheImpl.Singleton;
    }
     
    Authentication getAuth(String filterName, String user) {
        Map<String,byte[]> map= getCache().cache.get(filterName);
        if (map==null)
            return null;
        for ( byte[] bytes : map.values()) {            
            Authentication auth = getCache().deserializeAuthentication(bytes); 
            Object o = auth.getPrincipal();
            
            if (o instanceof UserDetails) {
                if (user.equals(((UserDetails)o).getUsername()))
                        return auth;                
            }
            if (o instanceof Principal) {
                if (user.equals(((Principal)o).getName()))
                        return auth;                
            }
            if (o instanceof String) {
                if (user.equals(((String)o)))
                        return auth;                
            }                
        }
        return null;
    }
    public void testBasicAuth() throws Exception{
        
                
        BasicAuthenticationFilterConfig config = new BasicAuthenticationFilterConfig();
        config.setClassName(GeoServerBasicAuthenticationFilter.class.getName());
        config.setUseRememberMe(false);
        config.setName(testFilterName);
        
        getSecurityManager().saveFilter(config);
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
            testFilterName,
            GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER,
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
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        
        // check success
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        

        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((testUserName+":"+testPassword).getBytes())));
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        Authentication auth = getAuth(testFilterName, testUserName);
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
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        auth = getAuth(testFilterName, "wrongpass");
        assertNull(auth);

        
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
        auth = getAuth("unknow", testPassword);
        assertNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // check root user
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
        
        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((GeoServerUser.ROOT_USERNAME+":geoserver").getBytes())));
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        auth = getAuth(GeoServerUser.ROOT_USERNAME, "geoserver");
        assertNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        

        
        // check disabled user        
        updateUser("ug1", testUserName, false);
        
        // since the cache is working, disabling has no effect
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.addHeader("Authorization",  "Basic " + 
                new String(Base64.encodeBytes((testUserName+":"+testPassword).getBytes())));
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        auth = getAuth(testFilterName, testUserName);
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, ((UserDetails) auth.getPrincipal()).getUsername());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));

        // clear cache, user should be disabled
        getCache().removeAll();

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
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        updateUser("ug1", testUserName, true);
        
    }
    
    public void testJ2eeProxy() throws Exception{

        J2eeAuthenticationFilterConfig config = new J2eeAuthenticationFilterConfig();        
        config.setClassName(GeoServerJ2eeAuthenticationFilter.class.getName());        
        config.setName(testFilterName3);
        config.setRoleServiceName("rs1");        
        getSecurityManager().saveFilter(config);
        
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
            testFilterName3,
            GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER,
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
        insertAnonymousFilter(GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER);
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
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
            testFilterName4,
            GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER,
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
        request.setHeader("principal", testUserName);
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();            
        getProxy().doFilter(request, response, chain);            
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        // Test anonymous
        insertAnonymousFilter(GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER);
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
                GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
                testFilterName2,
                GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER,
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
        insertAnonymousFilter(GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER);
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
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
            testFilterName5,
            GeoServerSecurityFilterChain.REMEMBER_ME_FILTER,
            GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER,
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

    protected void prepareFormFiltersForTest() {
        
         GeoServerCompositeFilter authFilter =
                (GeoServerCompositeFilter)
                getProxy().getFilters("/j_spring_security_foo_check").get(1);
        
        if (authFilter instanceof GeoServerUserNamePasswordAuthenticationFilter) {
            UsernamePasswordAuthenticationFilter authFilter2 = (UsernamePasswordAuthenticationFilter) 
                    authFilter.getNestedFilters().get(0);
            authFilter2.setFilterProcessesUrl("/j_spring_security_foo_check");
        }

        authFilter =
                (GeoServerCompositeFilter)
                getProxy().getFilters("/j_spring_security_foo_logout").get(1);

        
        if (authFilter instanceof GeoServerLogoutFilter) {
            LogoutFilter authFilter2 = (LogoutFilter) 
                    authFilter.getNestedFilters().get(0);
            authFilter2.setFilterProcessesUrl("/j_spring_security_foo_logout");
        }
        
    }
    
    public void testFormLogin() throws Exception {
            
            
        UsernamePasswordAuthenticationFilterConfig config = new UsernamePasswordAuthenticationFilterConfig();
        config.setClassName(GeoServerUserNamePasswordAuthenticationFilter.class.getName());
        config.setUsernameParameterName("username");
        config.setPasswordParameterName("password");
        config.setName(testFilterName6);
        getSecurityManager().saveFilter(config);
        
        LogoutFilterConfig loConfig = new LogoutFilterConfig();
        loConfig.setClassName(GeoServerLogoutFilter.class.getName());
        loConfig.setName(testFilterName9);
        getSecurityManager().saveFilter(loConfig);
        
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,
            GeoServerSecurityFilterChain.GUI_EXCEPTION_TRANSLATION_FILTER,
            GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);

        
        prepareFiterChain("/j_spring_security_foo_check",
                GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
                testFilterName6);

        prepareFiterChain("/j_spring_security_foo_logout",
                GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
                testFilterName9);
        
        prepareFormFiltersForTest();        
        SecurityContextHolder.getContext().setAuthentication(null);
        
        
        // Test entry point                
        MockHttpServletRequest request= createRequest("/foo/bar");
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();        
        
        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        String tmp = response.getHeader("Location");
        assertTrue(tmp.endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_FORM));
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        
        
        // check success
        request= createRequest("/j_spring_security_foo_check");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.setMethod("POST");
        request.setupAddParameter(config.getUsernameParameterName(), testUserName);
        request.setupAddParameter(config.getPasswordParameterName(), testPassword);
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_SUCCCESS));
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

        // Test logout                
                
        request= createRequest("/j_spring_security_foo_logout");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        tmp = response.getHeader("Location");
        assertNotNull(tmp);
        assertTrue(tmp.endsWith(GeoServerLogoutFilter.URL_AFTER_LOGOUT));
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        
        
        // test invalid password
        request= createRequest("/j_spring_security_foo_check");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.setMethod("POST");
        request.setupAddParameter(config.getUsernameParameterName(), testUserName);
        request.setupAddParameter(config.getPasswordParameterName(), "wrongpass");
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_FAILURE));

        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        // check unknown user
        request= createRequest("/j_spring_security_foo_check");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.setMethod("POST");
        request.setupAddParameter(config.getUsernameParameterName(), "unknwon");
        request.setupAddParameter(config.getPasswordParameterName(), testPassword);
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_FAILURE));
        
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // check root user
        request= createRequest("/j_spring_security_foo_check");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.setMethod("POST");
        request.setupAddParameter(config.getUsernameParameterName(), GeoServerUser.ROOT_USERNAME);
        request.setupAddParameter(config.getPasswordParameterName(), "geoserver");
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_SUCCCESS));
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
        request= createRequest("/j_spring_security_foo_check");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.setMethod("POST");
        request.setupAddParameter(config.getUsernameParameterName(), GeoServerUser.ROOT_USERNAME);
        request.setupAddParameter(config.getPasswordParameterName(), "geoserver1");
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_FAILURE));
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        
        // check disabled user
        updateUser("ug1", testUserName, false);
        request= createRequest("/j_spring_security_foo_check");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.setMethod("POST");
        request.setupAddParameter(config.getUsernameParameterName(), testUserName);
        request.setupAddParameter(config.getPasswordParameterName(), testPassword);
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_FAILURE));
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        updateUser("ug1", testUserName, true);
        
        // Test anonymous
        insertAnonymousFilter(GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER);
        request= createRequest("foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        // Anonymous context is not stored in http session, no further testing
        removeAnonymousFilter();

        

    }

    
    public void testFormLoginWithRememberMe() throws Exception{
        
        
        UsernamePasswordAuthenticationFilterConfig config = new UsernamePasswordAuthenticationFilterConfig();
        config.setClassName(GeoServerUserNamePasswordAuthenticationFilter.class.getName());
        config.setUsernameParameterName("username");
        config.setPasswordParameterName("password");
        config.setName(testFilterName7);
        getSecurityManager().saveFilter(config);
        
        LogoutFilterConfig loConfig = new LogoutFilterConfig();
        loConfig.setClassName(GeoServerLogoutFilter.class.getName());
        loConfig.setName(testFilterName9);
        getSecurityManager().saveFilter(loConfig);
        
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,
            GeoServerSecurityFilterChain.REMEMBER_ME_FILTER,
            GeoServerSecurityFilterChain.GUI_EXCEPTION_TRANSLATION_FILTER,
            GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);
        
        prepareFiterChain("/j_spring_security_foo_logout",
                GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,            
                testFilterName9);
        
        prepareFiterChain("/j_spring_security_foo_check",
                GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
                testFilterName7);

        
        prepareFormFiltersForTest();        
        SecurityContextHolder.getContext().setAuthentication(null);

        

        // Test entry point                
        MockHttpServletRequest request= createRequest("/foo/bar");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();        
                
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        String tmp = response.getHeader("Location");
        assertTrue(tmp.endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_FORM));
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());                    

        //check success
        request= createRequest("/j_spring_security_foo_check");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.setMethod("POST");
        request.setupAddParameter(config.getUsernameParameterName(), testUserName);
        request.setupAddParameter(config.getPasswordParameterName(), testPassword);
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_SUCCCESS));
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
        assertEquals(1,response.getCookies().size());
        Cookie cookie = (Cookie) response.getCookies().get(0);
        assertNotNull(cookie.getValue());
        
          
        // check logout
        request= createRequest("/j_spring_security_foo_logout");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();        
        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        tmp = response.getHeader("Location");
        assertNotNull(tmp);
        assertTrue(tmp.endsWith(GeoServerLogoutFilter.URL_AFTER_LOGOUT));
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        Cookie cancelCookie = (Cookie) response.getCookies().get(0);
        assertNull(cancelCookie.getValue());


        // check no remember me for root user
        request= createRequest("/j_spring_security_foo_check");
        request.setupAddParameter("_spring_security_remember_me", "yes");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        request.setMethod("POST");
        request.setupAddParameter(config.getUsernameParameterName(), GeoServerUser.ROOT_USERNAME);
        request.setupAddParameter(config.getPasswordParameterName(), "geoserver");
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_SUCCCESS));
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNotNull(ctx);
        auth = ctx.getAuthentication();
        assertNotNull(auth);
        //checkForAuthenticatedRole(auth);
        assertEquals(GeoServerUser.ROOT_USERNAME,auth.getPrincipal());
        assertEquals(0,response.getCookies().size());
        
        // check disabled user
        updateUser("ug1", testUserName, false);
        
        request= createRequest("/foo/bar");
        request.addCookie(cookie);        
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        tmp = response.getHeader("Location");
        assertTrue(tmp.endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_FORM));
        // check for cancel cookie
        assertEquals(1,response.getCookies().size());
        cancelCookie = (Cookie) response.getCookies().get(0);
        assertNull(cancelCookie.getValue());
        updateUser("ug1", testUserName, true);
       
        

    }

    public void testX509Auth() throws Exception{

        X509CertificateAuthenticationFilterConfig config = 
                new X509CertificateAuthenticationFilterConfig();        
        config.setClassName(GeoServerX509CertificateAuthenticationFilter.class.getName());        
        config.setName(testFilterName8);
        config.setRoleServiceName("rs1");
        config.setRoleSource(org.geoserver.security.config.X509CertificateAuthenticationFilterConfig.RoleSource.RoleService);
        config.setUserGroupServiceName("ug1");
        getSecurityManager().saveFilter(config);
        
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,    
            testFilterName8,
            GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER,
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
        
        
        for (org.geoserver.security.config.X509CertificateAuthenticationFilterConfig.RoleSource rs : 
            org.geoserver.security.config.X509CertificateAuthenticationFilterConfig.RoleSource.values()) {
            config.setRoleSource(rs);
            getSecurityManager().saveFilter(config);
            request= createRequest("/foo/bar");
            response= new MockHttpServletResponse();
            chain = new MockFilterChain();
            setCertifacteForUser(testUserName, request);                        
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
        for (org.geoserver.security.config.X509CertificateAuthenticationFilterConfig.RoleSource rs : 
            org.geoserver.security.config.X509CertificateAuthenticationFilterConfig.RoleSource.values()) {
            config.setRoleSource(rs);
            getSecurityManager().saveFilter(config);

            config.setRoleSource(rs);
            request= createRequest("/foo/bar");
            response= new MockHttpServletResponse();
            chain = new MockFilterChain();
            //TODO
            setCertifacteForUser("unknown", request);
            getProxy().doFilter(request, response, chain);            
            assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
            ctx = (SecurityContext)request.getSession(true).getAttribute(
                    HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
            assertNotNull(ctx);
            Authentication auth = ctx.getAuthentication();
            assertNotNull(auth);
            assertNull(SecurityContextHolder.getContext().getAuthentication());
            checkForAuthenticatedRole(auth);
            assertEquals("unknown", auth.getPrincipal());
        }

        // test disabled user
        updateUser("ug1", testUserName, false);
        config.setRoleSource(org.geoserver.security.config.X509CertificateAuthenticationFilterConfig.RoleSource.UGService);
        getSecurityManager().saveFilter(config);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();
        setCertifacteForUser(testUserName, request);
        getProxy().doFilter(request, response, chain);            
        assertEquals(HttpServletResponse.SC_FORBIDDEN,response.getErrorCode());
        ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        
        // Test anonymous
        insertAnonymousFilter(GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER);
        request= createRequest("/foo/bar");
        response= new MockHttpServletResponse();
        chain = new MockFilterChain();                        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        // Anonymous context is not stored in http session, no further testing
        removeAnonymousFilter();

                
    }      
    
    protected void setCertifacteForUser(final String userName, MockHttpServletRequest request) {
        X509Certificate x509 = new X509Certificate() {

            @Override
            public Set<String> getCriticalExtensionOIDs() {
                return null;
            }

            @Override
            public byte[] getExtensionValue(String arg0) {
                return null;
            }

            @Override
            public Set<String> getNonCriticalExtensionOIDs() {
                return null;
            }

            @Override
            public boolean hasUnsupportedCriticalExtension() {
                return false;
            }

            @Override
            public void checkValidity() throws CertificateExpiredException,
                    CertificateNotYetValidException {
            }

            @Override
            public void checkValidity(Date arg0) throws CertificateExpiredException,
                    CertificateNotYetValidException {
            }

            @Override
            public int getBasicConstraints() {
                return 0;
            }

            @Override
            public Principal getIssuerDN() {
                return null;
            }

            @Override
            public boolean[] getIssuerUniqueID() {
                return null;
            }

            @Override
            public boolean[] getKeyUsage() {
                return null;
            }

            @Override
            public Date getNotAfter() {
                return null;
            }

            @Override
            public Date getNotBefore() {
                return null;
            }

            @Override
            public BigInteger getSerialNumber() {
                return null;
            }

            @Override
            public String getSigAlgName() {
                return null;
            }

            @Override
            public String getSigAlgOID() {
                return null;
            }

            @Override
            public byte[] getSigAlgParams() {
                return null;
            }

            @Override
            public byte[] getSignature() {
                return null;
            }

            @Override
            public Principal getSubjectDN() {
                return new Principal () {
                 @Override
                public String getName() {
                     return "cn="+userName+",ou=ou1";
                     }   
                };
            }

            @Override
            public boolean[] getSubjectUniqueID() {
                return null;
            }

            @Override
            public byte[] getTBSCertificate() throws CertificateEncodingException {
                return null;
            }

            @Override
            public int getVersion() {
                return 0;
            }

            @Override
            public byte[] getEncoded() throws CertificateEncodingException {
                return null;
            }

            @Override
            public PublicKey getPublicKey() {
                return null;
            }

            @Override
            public String toString() {
                return null;
            }

            @Override
            public void verify(PublicKey arg0) throws CertificateException,
                    NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
                    SignatureException {
            }

            @Override
            public void verify(PublicKey arg0, String arg1) throws CertificateException,
                    NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException,
                    SignatureException {
            }
            
        };
        request.setAttribute("javax.servlet.request.X509Certificate", 
                new X509Certificate[]{x509});
    }

    public void testCascadingFilters() throws Exception{

        BasicAuthenticationFilterConfig bconfig = new BasicAuthenticationFilterConfig();
        bconfig.setClassName(GeoServerBasicAuthenticationFilter.class.getName());
        bconfig.setUseRememberMe(false);
        bconfig.setName(testFilterName);
        getSecurityManager().saveFilter(bconfig);

        
        DigestAuthenticationFilterConfig config = new DigestAuthenticationFilterConfig();
        config.setClassName(GeoServerDigestAuthenticationFilter.class.getName());
        config.setName(testFilterName2);
        config.setUserGroupServiceName("ug1");
        
        getSecurityManager().saveFilter(config);
        prepareFiterChain(pattern,
                GeoServerSecurityFilterChain.SECURITY_CONTEXT_NO_ASC_FILTER,
                testFilterName,
                testFilterName2,
                GeoServerSecurityFilterChain.DYNAMIC_EXCEPTION_TRANSLATION_FILTER,
                GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);


        SecurityContextHolder.getContext().setAuthentication(null);
            
        // Test entry point, must be digest                
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
        
        
        // test successful login for digest
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
        
        // check success for basic authentication
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
        auth = ctx.getAuthentication();
        assertNotNull(auth);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        checkForAuthenticatedRole(auth);
        assertEquals(testUserName, ((UserDetails) auth.getPrincipal()).getUsername());
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));

    }
    
}
