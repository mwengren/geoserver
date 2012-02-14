/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.web.user;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.wicket.markup.html.form.ChoiceRenderer;
import org.apache.wicket.markup.html.form.SubmitLink;
import org.apache.wicket.model.IModel;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.impl.GeoServerUserGroup;
import org.geoserver.security.web.PaletteFormComponent;
import org.geoserver.security.web.group.NewGroupPage;
import org.geoserver.web.GeoServerApplication;

/**
 * A form component that can be used to edit user to group assignments
 */
public class UserGroupPaletteFormComponent extends PaletteFormComponent<GeoServerUserGroup> {

    private static final long serialVersionUID = 1L;

    GeoServerUser user;

    public UserGroupPaletteFormComponent(String id, final String ugServiceName, GeoServerUser user) {
        super(id, new SelectedGroupsModel(ugServiceName, user), new GroupsModel(ugServiceName), 
            new ChoiceRenderer<GeoServerUserGroup>("groupname", "groupname"));

//        if (behavior==null) {
//            groupPalette = new Palette<GeoServerUserGroup>(
//                "groups", model,choicesModel,
//                new ChoiceRenderer<GeoServerUserGroup>("groupname","groupname"), 10, false);
//        } else {
//            groupPalette = new Palette<GeoServerUserGroup>(
//                    "groups", model,choicesModel,
//                    new ChoiceRenderer<GeoServerUserGroup>("groupname","groupname"), 10, false) {
//                        private static final long serialVersionUID = 1L;
//
//                        @Override
//                        protected Recorder<GeoServerUserGroup> newRecorderComponent() {                            
//                            Recorder<GeoServerUserGroup> r= super.newRecorderComponent();
//                            r.add(behavior);
//                            return r;
//                        }                                        
//            };            
//        }
        //palette.setOutputMarkupId(true);

        add(new SubmitLink("addGroup") {
            @Override
            public void onSubmit() {
                setResponsePage(new NewGroupPage(ugServiceName).setReturnPage(this.getPage()));
            }
        });
    }

    public List<GeoServerUserGroup> getSelectedGroups() {
        return new ArrayList(palette.getModelCollection());
    }

    public void diff(Collection<GeoServerUserGroup> orig, Collection<GeoServerUserGroup> add, 
        Collection<GeoServerUserGroup> remove) {
        
        remove.addAll(orig);
        for (GeoServerUserGroup group : getSelectedGroups()) {
            if (!orig.contains(group)) {
                add.add(group);
            }
            else {
                remove.remove(group);
            }
        }
    }
//
//    @Override
//    public void updateModel() {
//        groupPalette.getRecorderComponent().updateModel();
//    }
//    
//    public Palette<GeoServerUserGroup> getGroupPalette() {
//        return groupPalette;
//    }

//    class SelectedGroupsModel implements IModel<List<GeoServerUserGroup>> {
//
//        String ugServiceName;
//        GeoServerUser user;
//
//        List<GeoServerUserGroup> groups;
//
//        SelectedGroupsModel(String ugServiceName, GeoServerUser user) {
//            this.ugServiceName = ugServiceName;
//            this.user = user;
//        }
//
//        @Override
//        public List<GeoServerUserGroup> getObject() {
//            if (groups == null) {
//                GeoServerSecurityManager secMgr = GeoServerApplication.get().getSecurityManager();
//                try {
//                    groups = 
//                        new ArrayList(secMgr.loadUserGroupService(ugServiceName).getGroupsForUser(user));
//                } catch (IOException e) {
//                    throw new RuntimeException(e);
//                }
//            }
//            return groups;
//        }
//
//        @Override
//        public void setObject(List<GeoServerUserGroup> object) {
//            this.groups = object;
//        }
//    
//        @Override
//        public void detach() {
//        }
//    }

    static class SelectedGroupsModel implements IModel<List<GeoServerUserGroup>> {
        List<GeoServerUserGroup> groups;

        public SelectedGroupsModel(String ugServiceName, GeoServerUser user) {
            try {
                GeoServerSecurityManager secMgr = GeoServerApplication.get().getSecurityManager();
                setObject(new ArrayList(secMgr.loadUserGroupService(ugServiceName).getGroupsForUser(user)));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public List<GeoServerUserGroup> getObject() {
            return groups;
        }

        @Override
        public void setObject(List<GeoServerUserGroup> object) {
            this.groups = object;
        }

        @Override
        public void detach() {
        }

    }
}
