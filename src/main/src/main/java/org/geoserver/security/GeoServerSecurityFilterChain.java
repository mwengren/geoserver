/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

/**
 * The security filter filter chain
 * 
 * The content of {@link #antPatterns} must be 
 * equal to the keys of {@link #filterMap}
 * 
 * The order of {@link #antPatterns} determines
 * the order of ant pattern matching used
 * by GeoServerSecurityFilterChainProxy
 * 
 * @author christian
 *
 */
public class GeoServerSecurityFilterChain  {

    private ArrayList<String> antPatterns;
    private HashMap<String,ArrayList<String>>  filterMap; 
    

    public static final String SECURITY_CONTEXT_ASC_FILTER = "securityContextAscFilter";
    public static final String SECURITY_CONTEXT_NO_ASC_FILTER = "securityContextNoAscFilter";
    
    public static final String SERVLET_API_SUPPORT_FILTER = "servletApiSupportFilter";

    public static final String FORM_LOGIN_FILTER = "formLoginFilter";

    public static final String REMEMBER_ME_FILTER = "rememberMeFilter";

    public static final String ANONYMOUS_FILTER = "anonymousFilter";

    public static final String BASIC_AUTH_FILTER = "basicAuthFilter";
    public static final String BASIC_AUTH_NO_REMEMBER_ME_FILTER = "basicAuthNoRememberMeFilter";

    public static final String EXCEPTION_TRANSLATION_FILTER = "exceptionTranslationFilter";
    public static final String EXCEPTION_TRANSLATION_OWS_FILTER = "exceptionTranslationOwsFilter";

    public static final String LOGOUT_FILTER = "logoutFilter";

    public static final String FILTER_SECURITY_INTERCEPTOR = "filterSecurityInterceptor";
    public static final String FILTER_SECURITY_REST_INTERCEPTOR = "filterSecurityRestInterceptor";
    
    public GeoServerSecurityFilterChain() {
        antPatterns = new ArrayList<String>();
        filterMap = new HashMap<String,ArrayList<String>>();   
    }
        
    /**
     * Constructor cloning all collections
     * 
     * @param other
     */
    public GeoServerSecurityFilterChain(GeoServerSecurityFilterChain other) {                
        this.antPatterns=new ArrayList<String>(other.antPatterns);        
        this.filterMap=new HashMap<String,ArrayList<String>>();
        for (String pattern: other.filterMap.keySet()) {
            this.filterMap.put(pattern, new  ArrayList<String>(other.getFilterMap().get(pattern)));
        }
    }
    
            
    /**
     * Create the initial {@link GeoServerSecurityFilterChain} 
     * 
     * @return
     */
    public static GeoServerSecurityFilterChain getInitialChain() {
        GeoServerSecurityFilterChain chain = new GeoServerSecurityFilterChain();
        chain.setAntPatterns(createListFromStrings(
                "/web/**","/j_spring_security_check/**","/j_spring_security_logout/**","/rest/**",
                "/gwc/rest/web/**","/gwc/rest/**","/**"));
        
        chain.filterMap.put("/web/**",
                createListFromStrings(SECURITY_CONTEXT_ASC_FILTER, LOGOUT_FILTER, 
                        FORM_LOGIN_FILTER, SERVLET_API_SUPPORT_FILTER, REMEMBER_ME_FILTER, ANONYMOUS_FILTER, 
                        EXCEPTION_TRANSLATION_FILTER, FILTER_SECURITY_INTERCEPTOR));
        
        chain.filterMap.put("/j_spring_security_check/**", 
                createListFromStrings(SECURITY_CONTEXT_ASC_FILTER, 
                LOGOUT_FILTER, FORM_LOGIN_FILTER, SERVLET_API_SUPPORT_FILTER, REMEMBER_ME_FILTER, 
                ANONYMOUS_FILTER, EXCEPTION_TRANSLATION_FILTER, FILTER_SECURITY_INTERCEPTOR));
            
        chain.filterMap.put("/j_spring_security_logout/**", 
                createListFromStrings(SECURITY_CONTEXT_ASC_FILTER, 
                LOGOUT_FILTER, FORM_LOGIN_FILTER, SERVLET_API_SUPPORT_FILTER, REMEMBER_ME_FILTER, 
                ANONYMOUS_FILTER, EXCEPTION_TRANSLATION_FILTER, FILTER_SECURITY_INTERCEPTOR));
            
        chain.filterMap.put("/rest/**", 
                createListFromStrings(SECURITY_CONTEXT_NO_ASC_FILTER, BASIC_AUTH_FILTER,
                ANONYMOUS_FILTER, EXCEPTION_TRANSLATION_OWS_FILTER, FILTER_SECURITY_REST_INTERCEPTOR));

        chain.filterMap.put("/gwc/rest/web/**",
                createListFromStrings(ANONYMOUS_FILTER, 
                EXCEPTION_TRANSLATION_FILTER, FILTER_SECURITY_INTERCEPTOR));

        chain.filterMap.put("/gwc/rest/**", 
                createListFromStrings(SECURITY_CONTEXT_NO_ASC_FILTER, 
                BASIC_AUTH_NO_REMEMBER_ME_FILTER, EXCEPTION_TRANSLATION_OWS_FILTER, 
                FILTER_SECURITY_REST_INTERCEPTOR));

         chain.filterMap.put("/**", 
                 createListFromStrings(SECURITY_CONTEXT_NO_ASC_FILTER, BASIC_AUTH_FILTER, 
                ANONYMOUS_FILTER, EXCEPTION_TRANSLATION_OWS_FILTER, FILTER_SECURITY_INTERCEPTOR));        
         
        return chain;
    }

    /**
     * Helper method to create a list
     * 
     * @param filterName
     * @return
     */
    protected static ArrayList<String> createListFromStrings(String... filterName) {
        
        return new ArrayList<String>(Arrays.asList(filterName));
    }
    
    public ArrayList<String> getAntPatterns() {
        return antPatterns;
    }

    public void setAntPatterns(ArrayList<String> antPatterns) {
        this.antPatterns = antPatterns;
    }

    public HashMap<String, ArrayList<String>> getFilterMap() {
        return filterMap;
    }

    public void setFilterMap(HashMap<String, ArrayList<String>> filterMap) {
        this.filterMap = filterMap;
    }

    /**
     * Convenience method, insert filter name at
     * first position for the given pattern
     * 
     * returns true on success
     * 
     * @param pattern
     * @param filterName
     * @return
     */
    public boolean insertFirst(String pattern, String filterName) {
        ArrayList<String> filterNames = filterMap.get(pattern);
        if (filterNames==null) return false;
        filterNames.add(0,filterName);
        return true;
    }
    
    /**
     * Convenience method, insert filter name at
     * last position for the given pattern
     * 
     * returns true on success
     * 
     * @param pattern
     * @param filterName
     * @return
     */
    public boolean insertLast(String pattern, String filterName) {
        ArrayList<String> filterNames = filterMap.get(pattern);
        if (filterNames==null) return false;
        filterNames.add(filterName);
        return true;
    }

    /**
     * Convenience method, insert filter name before
     * filter named positionName for the given pattern
     * 
     * returns true on success
     * 
     * @param pattern
     * @param filterName
     * @param poslitionName
     * @return
     */
    public boolean insertBefore(String pattern, String filterName, String positionName) {
        ArrayList<String> filterNames = filterMap.get(pattern);
        if (filterNames==null) return false;
        int index = filterNames.indexOf(positionName);
        if (index==-1) return false;
        filterNames.add(index,filterName);
        return true;
    }
    
    /**
     * Convenience method, insert filter name after
     * filter named positionName for the given pattern
     * 
     * returns true on success
     * 
     * @param pattern
     * @param filterName
     * @param poslitionName
     * @return
     */
    public boolean insertAfter(String pattern, String filterName, String positionName) {
        ArrayList<String> filterNames = filterMap.get(pattern);
        if (filterNames==null) return false;
        int index = filterNames.indexOf(positionName);
        if (index==-1) return false;
        filterNames.add(index+1,filterName);
        return true;
    }

    /**
     * Get a list of patterns having the filter in their chain
     * 
     * @param filterName
     * @return
     */
    public List<String> patternsContainingFilter(String filterName) {
        List<String> result = new ArrayList<String>();
        for (String pattern: antPatterns) {
            if (filterMap.get(pattern).contains(filterName)) {
                result.add(pattern);
            }
        }
        return result;
    }    
}
