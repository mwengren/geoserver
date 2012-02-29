/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */

package org.geoserver.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Filter with nested {@link Filter} objects
 * 
 * @author mcr
 *
 */
public class GeoServerComplexFilter extends GeoServerSecurityFilter {
    
    protected  class NestedFilterChain implements FilterChain {
        private final FilterChain originalChain;
        private int currentPosition = 0;

        private NestedFilterChain( FilterChain chain) {
            this.originalChain = chain;
        }

        public void doFilter(final ServletRequest request, final ServletResponse response) throws IOException, ServletException {
            if (nestedFilters == null || currentPosition == nestedFilters.size()) {
                originalChain.doFilter(request, response);
            } else {
                currentPosition++;
                Filter nextFilter = nestedFilters.get(currentPosition - 1);
                nextFilter.doFilter(request, response, this);
            }
        }

    }

    
    protected List<Filter> nestedFilters = new ArrayList<Filter>();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (nestedFilters == null || nestedFilters.size()==0) {
            chain.doFilter(request, response);
            return;
        }
        
        NestedFilterChain nestedChain = new NestedFilterChain( chain );
        nestedChain.doFilter(request, response);

    }
    
    public List<Filter> getNestedFilters() {
        return nestedFilters;
    }

    public void setNestedFilters(List<Filter> nestedFilters) {
        this.nestedFilters = nestedFilters;
    }        
}
