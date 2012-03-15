package org.geoserver.security.auth;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.geoserver.security.GeoServerSecurityFilterChain;
import org.geoserver.security.config.CasAuthenticationFilterConfig;
import org.geoserver.security.config.ExceptionTranslationFilterConfig;
import org.geoserver.security.config.LogoutFilterConfig;
import org.geoserver.security.config.UsernamePasswordAuthenticationFilterConfig;
import org.geoserver.security.filter.GeoServerCasAuthenticationFilter;
import org.geoserver.security.filter.GeoServerExceptionTranslationFilter;
import org.geoserver.security.filter.GeoServerLogoutFilter;
import org.geoserver.security.filter.GeoServerUserNamePasswordAuthenticationFilter;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import com.mockrunner.mock.web.MockFilterChain;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;

public class CasAuthenticationTest extends AbstractAuthenticationProviderTest {

    public final String casFilterName="testCasFilter";
    public final String CAS_EXCEPTION_TRANSLATION_FILTER="casExceptionTranslationFilter";
    
    String loginUrl;
    String ticketUrl;
    String serviceUrl;
    
    protected String getCookieValue(HttpURLConnection conn) {
        for (int i=0; ; i++) {
            String headerName = conn.getHeaderFieldKey(i);
            String headerValue = conn.getHeaderField(i);

            if (headerName == null && headerValue == null) {
                // No more headers
                break;
            }
            if ("Set-Cookie".equalsIgnoreCase(headerName)) {
                return headerValue;
            }
                // Parse cookie
//                String[] fields = headerValue.split(";\\s*");
//
//                String cookieValue = fields[0];
//                String expires = null;
//                String path = null;
//                String domain = null;
//                boolean secure = false;
//
//                // Parse each field
//                for (int j=1; j<fields.length; j++) {
//                    if ("secure".equalsIgnoreCase(fields[j])) {
//                        secure = true;
//                    } else if (fields[j].indexOf('=') > 0) {
//                        String[] f = fields[j].split("=");
//                        if ("expires".equalsIgnoreCase(f[0])) {
//                            expires = f[1];
//                        } else if ("domain".equalsIgnoreCase(f[0])) {
//                            domain = f[1];
//                        } else if ("path".equalsIgnoreCase(f[0])) {
//                            path = f[1];
//                        }
//                    }
//                }                
//            }
        }
        return null;
    }
    
    
    public void testFormLogin() throws Exception {
        
        
        loginUrl="http://ux-server02:8080/cas/login";
        ticketUrl="http://ux-server02:8080/cas";
        serviceUrl="http://localhost:8080/geoserver/j_spring_cas_security_check";
        
        CasAuthenticationFilterConfig config = new CasAuthenticationFilterConfig();
        config.setClassName(GeoServerCasAuthenticationFilter.class.getName());
        config.setLoginUrl(loginUrl);
        config.setService(serviceUrl);
        config.setTicketValidatorUrl(ticketUrl);        
        config.setName(casFilterName);        
        config.setUserGroupServiceName("ug1");
        getSecurityManager().saveFilter(config);
        
        ExceptionTranslationFilterConfig exConfig = new ExceptionTranslationFilterConfig();
        exConfig.setClassName(GeoServerExceptionTranslationFilter.class.getName());
        exConfig.setName(CAS_EXCEPTION_TRANSLATION_FILTER);
        exConfig.setAccessDeniedErrorPage("/denied.jsp");
        exConfig.setAuthenticationFilterName(casFilterName);
        getSecurityManager().saveFilter(exConfig);

                
        prepareFiterChain(pattern,
            GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,
            CAS_EXCEPTION_TRANSLATION_FILTER,
            GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);

        
        prepareFiterChain("/j_spring_cas_security_check",
                GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,    
                casFilterName);

        SecurityContextHolder.getContext().setAuthentication(null);
        
        
        // Test entry point                
        MockHttpServletRequest request= createRequest("/foo/bar");
        MockHttpServletResponse response= new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();        
        
        
        getProxy().doFilter(request, response, chain);
        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
        assertTrue(response.wasRedirectSent());
        String casLogin = response.getHeader("Location");
        assertNotNull(casLogin);
        assertTrue(casLogin.startsWith(loginUrl));
        
        URL casLoginURL= new URL(casLogin);    
        assertTrue(casLoginURL.getQuery().startsWith("service="));        
        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
        assertNull(ctx);
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        // Execute redirect to cas login page
        HttpURLConnection conn = (HttpURLConnection) casLoginURL.openConnection();
        InputStreamReader in = new InputStreamReader(conn.getInputStream());
        char[] array = new char[1024];
        int len;
        StringBuffer buff=new StringBuffer();
        while ((len =in.read(array))!=-1) {
            for (int i = 0; i < len; i++)
                buff.append(array[i]);
        }
        in.close();
        assertTrue(buff.toString().contains("username"));
        assertTrue(buff.toString().contains("password"));
        System.out.println(buff.toString());
        String cookieValue = getCookieValue(conn);
        assertNotNull(cookieValue);
/*        
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

  */      

    }

}
