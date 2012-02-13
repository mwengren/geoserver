package org.geoserver.security.web.user;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.wicket.WicketRuntimeException;
import org.apache.wicket.model.LoadableDetachableModel;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.impl.GeoServerUserGroup;
import org.geoserver.web.GeoServerApplication;

public class GroupsModel extends LoadableDetachableModel<Collection<GeoServerUserGroup>> {

    String userGroupServiceName;

    public GroupsModel(String userGroupServiceName) {
        this.userGroupServiceName = userGroupServiceName;
    }

    @Override
    protected Collection<GeoServerUserGroup> load() {
        GeoServerSecurityManager secMgr = GeoServerApplication.get().getSecurityManager();
        try {
            return new ArrayList(secMgr.loadUserGroupService(userGroupServiceName).getUserGroups());
        }
        catch(IOException e) {
            throw new WicketRuntimeException(e);
        }
    }

}
