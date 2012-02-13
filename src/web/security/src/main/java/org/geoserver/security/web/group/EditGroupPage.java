/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.web.group;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.geoserver.security.GeoServerRoleStore;
import org.geoserver.security.GeoServerUserGroupStore;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUserGroup;
import org.geoserver.security.validation.RoleStoreValidationWrapper;
import org.geoserver.security.validation.UserGroupStoreValidationWrapper;

public class EditGroupPage extends AbstractGroupPage {

    public EditGroupPage(String userGroupServiceName,GeoServerUserGroup group) {
        super(userGroupServiceName, group.copy()); //copy before passing into parent

        //name not changable on edit 
        get("form:groupname").setEnabled(false);
    }

    @Override
    protected void onFormSubmit(GeoServerUserGroup group) throws IOException {
        GeoServerUserGroupStore store = null;
        try {
            if (hasUserGroupStore(userGroupServiceName)) {
                store = new UserGroupStoreValidationWrapper(getUserGroupStore(userGroupServiceName));
                store.updateGroup(group);
                store.store();
            };
        } catch (IOException ex) {
            try {
                //try to reload the store
                store.load(); 
            } catch (IOException ex2) {};
            throw ex;
        }

        GeoServerRoleStore gaStore = null;
        try {
            if (hasRoleStore(getSecurityManager().getActiveRoleService().getName())) {
                gaStore = getRoleStore(getSecurityManager().getActiveRoleService().getName());
                gaStore = new RoleStoreValidationWrapper(gaStore);

                Set<GeoServerRole> orig = gaStore.getRolesForGroup(group.getGroupname());
                Set<GeoServerRole> add = new HashSet<GeoServerRole>();
                Set<GeoServerRole> remove = new HashSet<GeoServerRole>();
                rolePalette.diff(orig, add, remove);

                for (GeoServerRole role : add)
                    gaStore.associateRoleToGroup(role, group.getGroupname());
                for (GeoServerRole role : remove)
                    gaStore.disAssociateRoleFromGroup(role, group.getGroupname());        
                gaStore.store();
            }        
        } catch (IOException ex) {
            try {gaStore.load(); } catch (IOException ex2) {};
            throw ex;
        }

    }

}
