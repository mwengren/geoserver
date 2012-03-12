/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org.  All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */
package org.geoserver.security.web.group;

import java.util.List;

import org.apache.wicket.Component;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.model.StringResourceModel;
import org.geoserver.security.impl.GeoServerUserGroup;
import org.geoserver.security.web.AbstractConfirmRemovalPanelTest;
import org.geoserver.web.ComponentBuilder;
import org.geoserver.web.FormTestPage;


public class ConfirmRemovalGroupPanelTest extends AbstractConfirmRemovalPanelTest<GeoServerUserGroup> {
    private static final long serialVersionUID = 1L;

    protected boolean disassociateRoles = false;
    
    protected void setupPanel(final List<GeoServerUserGroup> roots) {
        tester.startPage(new FormTestPage(new ComponentBuilder() {
            private static final long serialVersionUID = 1L;

            public Component buildComponent(String id) {
                Model<Boolean> model = new Model<Boolean>(disassociateRoles);
                return new ConfirmRemovalGroupPanel(id, model,roots.toArray(new GeoServerUserGroup[roots.size()])) {
                    @Override
                    protected IModel<String> canRemove(GeoServerUserGroup data) {
                        SelectionGroupRemovalLink link = new SelectionGroupRemovalLink(getUserGroupServiceName(),"XXX",null,null,disassociateRoles);
                        return link.canRemove(data);
                    }

                    private static final long serialVersionUID = 1L;                    
                };
            }
        }));
    }
    
    public void testRemoveGroup() throws Exception {
        disassociateRoles=false;
        initializeForXML();
        removeObject();                                       
    }

    public void testRemoveGroupWithRoles() throws Exception {
        disassociateRoles=true;
        initializeForXML();
        removeObject();                                       
    }

    

    @Override
    protected GeoServerUserGroup getRemoveableObject() throws Exception{
        if (disassociateRoles)
            return ugService.createGroupObject("g_all", true);
        else
            return ugService.getGroupByGroupname("group1");
    }

    @Override
    protected GeoServerUserGroup getProblematicObject() throws Exception {
        return null;
    }

    @Override
    protected String getProblematicObjectRegExp() throws Exception{
        return "";
    }

    @Override
    protected String getRemoveableObjectRegExp() throws Exception{
        if (disassociateRoles)
            return ".*"+getRemoveableObject().getGroupname()+".*ROLE_WMS.*";
        else    
            return ".*"+getRemoveableObject().getGroupname()+".*";
    }    


}
