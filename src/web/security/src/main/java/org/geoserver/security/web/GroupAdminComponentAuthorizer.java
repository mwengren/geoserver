package org.geoserver.security.web;

import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.web.AdminComponentAuthorizer;
import org.springframework.security.core.Authentication;

public class GroupAdminComponentAuthorizer extends AdminComponentAuthorizer {

    @Override
    public boolean isAccessAllowed(Class componentClass,
            Authentication authentication) {

        //full admin implies group admin
        if (super.isAccessAllowed(componentClass, authentication)) {
            return true;
        }

        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        if (authentication.getPrincipal() instanceof GeoServerUser) {
            GeoServerUser user = (GeoServerUser) authentication.getPrincipal();
            //return user.isGroupAdmin();
        }
        
        return false;
    }
}
