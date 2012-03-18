package org.geoserver.security.cas;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.geoserver.security.GeoServerSecurityFilterChain;
import org.geoserver.security.auth.AbstractAuthenticationProviderTest;
import org.geoserver.security.cas.CasAuthenticationFilterConfig;
import org.geoserver.security.cas.GeoServerCasAuthenticationFilter;
import org.geoserver.security.config.ExceptionTranslationFilterConfig;
import org.geoserver.security.config.LogoutFilterConfig;
import org.geoserver.security.config.UsernamePasswordAuthenticationFilterConfig;
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
    
    
    public String doLogin(URL siteUrl, Map<String, String> data, String cookie ) throws Exception {
        
        boolean follow = HttpURLConnection.getFollowRedirects();
        HttpURLConnection.setFollowRedirects(false);
        HttpURLConnection conn = (HttpURLConnection) siteUrl.openConnection();
        HttpURLConnection.setFollowRedirects(follow);
        
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setDoInput(true);
        conn.setRequestProperty("Cookie", cookie);
        DataOutputStream out = new DataOutputStream(conn.getOutputStream());
        
        StringBuffer buff = new StringBuffer();
        for (Entry<String,String> entry : data.entrySet()) {
            if (buff.length()>0)
                buff.append("&");
            buff.append(entry.getKey()).append("=").
                append(URLEncoder.encode(entry.getValue(),"utf-8"));
        }
        //System.out.println(content);
        
        out.writeBytes(buff.toString());
        out.flush();
        out.close();
        assertEquals(302, conn.getResponseCode());
        return getResponseHeaderValue(conn, "Location");
    }
    
    protected String getResponseHeaderValue(HttpURLConnection conn,String name) {
        for (int i=0; ; i++) {
            String headerName = conn.getHeaderFieldKey(i);
            String headerValue = conn.getHeaderField(i);

            if (headerName == null && headerValue == null) {
                // No more headers
                break;
            }
            if (name.equalsIgnoreCase(headerName)) {
                return headerValue;
            }
        }
        return null;
    }
    
    String extractValue(String searchString, String buff) {
        int index = buff.indexOf(searchString);
        index+=searchString.length();
        int index2 = buff.indexOf("\"", index);
        return  buff.substring(index,index2);
    }

    String getCasTicket() throws Exception {
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
        
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line = "";
        StringBuffer buff=new StringBuffer();
        while((line=in.readLine())!=null) {
                buff.append(line);
        }
        in.close();

        
        assertTrue(buff.toString().contains("username"));
        assertTrue(buff.toString().contains("password"));
        
        String actionValue=extractValue("action=\"", buff.toString());
        
        URL url = new URL(casLoginURL.getProtocol(),
                casLoginURL.getHost(),casLoginURL.getPort(),
                actionValue);        
        //System.out.println(buff.toString());
        String cookieValue = getResponseHeaderValue(conn, "Set-Cookie");
        assertNotNull(cookieValue);
        
        Map<String,String> paramMap = new HashMap<String,String>();
        paramMap.put("username","castest");
        paramMap.put("password","castest");
        paramMap.put("_eventId","submit");
        paramMap.put("submit","LOGIN");
        
        String lt =extractValue("name=\"lt\" value=\"", buff.toString());
        assertNotNull(lt);
        String execution=extractValue("name=\"execution\" value=\"", buff.toString());
        assertNotNull(execution);
        paramMap.put("lt", lt);
        paramMap.put("execution", execution);
        String redirectAfterLogin = doLogin(url, paramMap, cookieValue);
        assertNotNull(redirectAfterLogin);
        assertTrue(redirectAfterLogin.startsWith(serviceUrl));
        int index = redirectAfterLogin.indexOf("ticket=");
        String ticket=redirectAfterLogin.substring(index+"ticket=".length());
        return ticket;
    }
    
    public void testCASLogin() throws Exception {
        
        // TODO: make online test
//        loginUrl="http://ux-server02:8080/cas/login";
//        ticketUrl="http://ux-server02:8080/cas";
//        serviceUrl="http://localhost:8080/geoserver/j_spring_cas_security_check";
//        
//        //HttpURLConnection.setFollowRedirects(false);
//        
//        CasAuthenticationFilterConfig config = new CasAuthenticationFilterConfig();
//        config.setClassName(GeoServerCasAuthenticationFilter.class.getName());
//        config.setLoginUrl(loginUrl);
//        config.setService(serviceUrl);
//        config.setTicketValidatorUrl(ticketUrl);        
//        config.setName(casFilterName);        
//        config.setUserGroupServiceName("ug1");
//        getSecurityManager().saveFilter(config);
//        
//        ExceptionTranslationFilterConfig exConfig = new ExceptionTranslationFilterConfig();
//        exConfig.setClassName(GeoServerExceptionTranslationFilter.class.getName());
//        exConfig.setName(CAS_EXCEPTION_TRANSLATION_FILTER);
//        exConfig.setAccessDeniedErrorPage("/denied.jsp");
//        exConfig.setAuthenticationFilterName(casFilterName);
//        getSecurityManager().saveFilter(exConfig);
//
//                
//        prepareFiterChain(pattern,
//            GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,
//            CAS_EXCEPTION_TRANSLATION_FILTER,
//            GeoServerSecurityFilterChain.FILTER_SECURITY_INTERCEPTOR);
//
//        
//        prepareFiterChain("/j_spring_cas_security_check",
//                GeoServerSecurityFilterChain.SECURITY_CONTEXT_ASC_FILTER,    
//                casFilterName);
//
//        SecurityContextHolder.getContext().setAuthentication(null);
//
//        
//
//        
//        MockHttpServletRequest request= createRequest("/j_spring_cas_security_check");
//        MockHttpServletResponse response= new MockHttpServletResponse();
//        MockFilterChain chain = new MockFilterChain();
//        String ticket = getCasTicket();
//        //request.setMethod("POST");
//        request.setupAddParameter("ticket",ticket);
//        getProxy().doFilter(request, response, chain);
//        assertEquals(HttpServletResponse.SC_OK, response.getErrorCode());
//        assertTrue(response.wasRedirectSent());
//        assertTrue(response.getHeader("Location").endsWith(GeoServerUserNamePasswordAuthenticationFilter.URL_LOGIN_SUCCCESS));
//        SecurityContext ctx = (SecurityContext)request.getSession(true).getAttribute(
//                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);        
//        assertNotNull(ctx);
//        Authentication auth = ctx.getAuthentication();
//        assertNotNull(auth);
//        assertNull(SecurityContextHolder.getContext().getAuthentication());
//        checkForAuthenticatedRole(auth);
//        assertEquals("castest", ((UserDetails) auth.getPrincipal()).getUsername());
//        assertTrue(auth.getAuthorities().contains(new GeoServerRole(rootRole)));
//        assertTrue(auth.getAuthorities().contains(new GeoServerRole(derivedRole)));

        
        ////////////////////////////////////////////////////////////////////////////////// TODO
        /*
        // Test logout                
                
        MockHttpServletRequest request= createRequest("/j_spring_cas_security_check");
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
