package org.geoserver.security.filter;

import org.geoserver.config.util.XStreamPersister;
import org.geoserver.security.config.SecurityNamedServiceConfig;

/**
 * Security provider for {@link GeoServerUserNamePasswordAuthenticationFilter}
 * 
 * @author mcr
 */
public class GeoServerUserNamePasswordAuthenticationProvider extends AbstractFilterProvider {

    @Override
    public void configure(XStreamPersister xp) {
        super.configure(xp);
        xp.getXStream().alias("usernamePasswordFilter", GeoServerUserNamePasswordAuthenticationFilter.class);
    }

    @Override
    public Class<? extends GeoServerSecurityFilter> getFilterClass() {
        return GeoServerUserNamePasswordAuthenticationFilter.class;
    }

    @Override
    public GeoServerSecurityFilter createFilter(SecurityNamedServiceConfig config) {
        return new GeoServerUserNamePasswordAuthenticationFilter();
    }

}
