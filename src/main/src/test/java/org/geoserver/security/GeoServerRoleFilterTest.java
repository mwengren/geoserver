package org.geoserver.security;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.config.SecurityManagerConfig;
import org.geoserver.security.impl.GeoServerRole;

import com.mockrunner.mock.web.MockFilterChain;
import com.mockrunner.mock.web.MockHttpServletRequest;
import com.mockrunner.mock.web.MockHttpServletResponse;

public class GeoServerRoleFilterTest extends GeoServerSecurityTestSupport {

    public void testFilterChainWithEnabled() throws Exception {
        enableRoleFilter(true);
        MockHttpServletRequest request = createRequest("/foo");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        GeoServerSecurityFilterChainProxy filterChainProxy = 
            GeoServerExtensions.bean(GeoServerSecurityFilterChainProxy.class);
        filterChainProxy.doFilter(request, response, chain);
        assertEquals(GeoServerRole.ANONYMOUS_ROLE.getAuthority(),response.getHeader("ROLES"));        
    }

    public void testFilterChainWithDisabled() throws Exception {
        enableRoleFilter(false);

        MockHttpServletRequest request = createRequest("/foo");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        
        GeoServerSecurityFilterChainProxy filterChainProxy = 
            GeoServerExtensions.bean(GeoServerSecurityFilterChainProxy.class);
        filterChainProxy.doFilter(request, response, chain);
        assertNull(response.getHeader("ROLES"));
        
    }


    void enableRoleFilter(boolean enabled) throws Exception {
        GeoServerSecurityManager secMgr = getSecurityManager();
        SecurityManagerConfig cfg = secMgr.getSecurityConfig();
        cfg.setIncludingRolesInResponse(enabled);
        cfg.setHttpResponseHeaderAttrForIncludedRoles(
                enabled ? "ROLES" : null);
        secMgr.saveSecurityConfig(cfg);
    }

}
