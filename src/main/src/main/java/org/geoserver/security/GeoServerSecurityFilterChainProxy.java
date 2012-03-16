package org.geoserver.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.auth.AuthenticationCacheImpl;
import org.geoserver.security.config.SecurityManagerConfig;
import org.geoserver.security.filter.GeoServerAnonymousAuthenticationFilter;
import org.geoserver.security.filter.GeoServerSecurityMetadataSource;
import org.geotools.util.logging.Logging;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

public class GeoServerSecurityFilterChainProxy extends FilterChainProxy 
    implements SecurityManagerListener, ApplicationContextAware  {
    
    static Logger LOGGER = Logging.getLogger("org.geoserver.security");

    static ThreadLocal<HttpServletRequest> REQUEST = new ThreadLocal<HttpServletRequest>();

    private boolean chainsInitialized;

    //security manager
    GeoServerSecurityManager securityManager;

    //app context
    ApplicationContext appContext;

    public GeoServerSecurityFilterChainProxy(GeoServerSecurityManager securityManager) {
        this.securityManager = securityManager;
        this.securityManager.addListener(this);
        chainsInitialized=false;
       
    }

/*    
    Map<String,List<String>> createDefaultFilterChain() {
        Map<String,List<String>> filterChain = new LinkedHashMap<String, List<String>>();
        
        filterChain.put("/web/**", Arrays.asList(SECURITY_CONTEXT_ASC_FILTER, LOGOUT_FILTER, 
            FORM_LOGIN_FILTER, SERVLET_API_SUPPORT_FILTER, REMEMBER_ME_FILTER, ANONYMOUS_FILTER, 
            EXCEPTION_TRANSLATION_FILTER, FILTER_SECURITY_INTERCEPTOR));

        filterChain.put("/j_spring_security_check/**", Arrays.asList(SECURITY_CONTEXT_ASC_FILTER, 
            LOGOUT_FILTER, FORM_LOGIN_FILTER, SERVLET_API_SUPPORT_FILTER, REMEMBER_ME_FILTER, 
            ANONYMOUS_FILTER, EXCEPTION_TRANSLATION_FILTER, FILTER_SECURITY_INTERCEPTOR));
        
        filterChain.put("/j_spring_security_logout/**", Arrays.asList(SECURITY_CONTEXT_ASC_FILTER, 
            LOGOUT_FILTER, FORM_LOGIN_FILTER, SERVLET_API_SUPPORT_FILTER, REMEMBER_ME_FILTER, 
            ANONYMOUS_FILTER, EXCEPTION_TRANSLATION_FILTER, FILTER_SECURITY_INTERCEPTOR));
        
        filterChain.put("/rest/**", Arrays.asList(SECURITY_CONTEXT_NO_ASC_FILTER, BASIC_AUTH_FILTER,
            ANONYMOUS_FILTER, EXCEPTION_TRANSLATION_OWS_FILTER, FILTER_SECURITY_REST_INTERCEPTOR));

        filterChain.put("/gwc/rest/web/**", Arrays.asList(ANONYMOUS_FILTER, 
            EXCEPTION_TRANSLATION_FILTER, FILTER_SECURITY_INTERCEPTOR));

        filterChain.put("/gwc/rest/**", Arrays.asList(SECURITY_CONTEXT_NO_ASC_FILTER, 
            BASIC_AUTH_NO_REMEMBER_ME_FILTER, EXCEPTION_TRANSLATION_OWS_FILTER, 
            FILTER_SECURITY_REST_INTERCEPTOR));

        filterChain.put("/**", Arrays.asList(SECURITY_CONTEXT_NO_ASC_FILTER, ROLE_FILTER,BASIC_AUTH_FILTER, 
            ANONYMOUS_FILTER, EXCEPTION_TRANSLATION_OWS_FILTER, FILTER_SECURITY_INTERCEPTOR));

        return filterChain;
    }
*/    

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.appContext = applicationContext;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        //set the request thread local
        REQUEST.set((HttpServletRequest) request);
        try {
            super.doFilter(request, response, chain);
        }
        finally {
            REQUEST.remove();
        }
    }

    @Override
    public void handlePostChanged(GeoServerSecurityManager securityManager) {
        createFilterChain();
    }

    public void afterPropertiesSet() {
        createFilterChain();
        super.afterPropertiesSet();
    };

    void createFilterChain() {

        
        SecurityManagerConfig config = securityManager.getSecurityConfig(); 
        GeoServerSecurityFilterChain filterChain = config.getFilterChain();
        
        Map<Object,List<Filter>> filterChainMap = new LinkedHashMap<Object,List<Filter>>();
                
        for (String pattern : filterChain.getAntPatterns()) {
            List<Filter> filters = new ArrayList<Filter>();
            for (String filterName : filterChain.getFilterMap().get(pattern)) {
                try {
                    Filter filter = lookupFilter(filterName);
                    if (filter == null) {
                        throw new NullPointerException("No filter named " + filterName +" could " +
                            "be found");
                    }

                    //check for anonymous auth flag
                    if (filter instanceof GeoServerAnonymousAuthenticationFilter && !config.isAnonymousAuth()) {
                        continue;
                    }
                    filters.add(filter);
                }
                catch(Exception ex) {
                    LOGGER.log(Level.SEVERE, "Error loading filter: " + filterName, ex);
                }
            }
            filterChainMap.put(pattern, filters);
        }

        synchronized (this) {
            // first, call destroy of all current filters        
            if (chainsInitialized) {
                for (Filter filter : obtainAllDefinedFilters()) {
                    filter.destroy();
                }
            }
            // empty cache since filter config  will change
            AuthenticationCacheImpl.get().removeAll();
            setFilterChainMap(filterChainMap);
            chainsInitialized=true;
        }
    }

    /**
     * looks up a named filter  
     */
    Filter lookupFilter(String filterName) throws IOException {
        Filter filter = securityManager.loadFilter(filterName);
//        if (filter == null) {
//            filter = (Filter) GeoServerExtensions.bean(filterName, appContext);
//        }
        return filter;
    }
}
