/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */
package org.geoserver.security.impl;

import java.util.Map.Entry;
import java.util.Collection;
import java.util.Properties;
import java.util.StringTokenizer;

import org.springframework.security.core.GrantedAuthority;

public class GeoServerRoleConverter {
    private String roleDelimiterString =";";
    private String roleParameterDelimiterString =",";
    private String roleParameterStartString = "(";
    private String roleParameterEndString = ")";
    private String roleParameterAssignmentString = "=";
    
    public String getRoleDelimiterString() {
        return roleDelimiterString;
    }
    public void setRoleDelimiterString(String roleDelimiterString) {
        this.roleDelimiterString = roleDelimiterString;
    }
    public String getRoleParameterDelimiterString() {
        return roleParameterDelimiterString;
    }
    public void setRoleParameterDelimiterString(String roleParameterDelimiterString) {
        this.roleParameterDelimiterString = roleParameterDelimiterString;
    }
    public String getRoleParameterStartString() {
        return roleParameterStartString;
    }
    public void setRoleParameterStartString(String roleParameterStartString) {
        this.roleParameterStartString = roleParameterStartString;
    }
    public String getRoleParameterEndString() {
        return roleParameterEndString;
    }
    public void setRoleParameterEndString(String roleParameterEndString) {
        this.roleParameterEndString = roleParameterEndString;
    }
    public String getRoleParameterAssignmentString() {
        return roleParameterAssignmentString;
    }
    public void setRoleParameterAssignmentString(String roleParameterAssignmentString) {
        this.roleParameterAssignmentString = roleParameterAssignmentString;
    }
    
    public String convertRoleToString(GeoServerRole role) {
        
        StringBuffer buff = new StringBuffer();
        writeRole(buff, role);
        return buff.toString();
    }
    
    protected void writeRole(StringBuffer buff,GeoServerRole role) {
        buff.append(role.getAuthority());
        Properties props = role.getProperties();
        
        if (props == null || props.isEmpty())
            return;
        
        buff.append(getRoleParameterStartString());
        boolean firstTime=true;
        for (Entry<Object,Object> entry : props.entrySet()) {
            if (firstTime==true)
                firstTime=false;
            else
                buff.append(getRoleParameterDelimiterString());
            buff.append(entry.getKey()).append(getRoleParameterAssignmentString());
            buff.append(entry.getValue()==null ? "" : entry.getValue());
        }
        buff.append(getRoleParameterEndString());        
    }
    
    public String convertRolesToString(Collection<GrantedAuthority> roles) {
        StringBuffer buff = new StringBuffer();
        boolean firstTime=true;
        for (GrantedAuthority role : roles) {
            if (firstTime==true)
                firstTime=false;
            else
                buff.append(getRoleDelimiterString());
            
            writeRole(buff, (GeoServerRole)role);
        }
        return buff.toString();
    }
    
    public GeoServerRole convertRoleFromString(String roleString, String userName) {
        GeoServerRole result = null;
        int index = roleString.indexOf(getRoleParameterStartString());        
        if (index == -1 ) {
            result= new GeoServerRole(roleString);
            result.setUserName(userName);
            return result;
        }
        
        result= new GeoServerRole(roleString.substring(0, index));
        result.setUserName(userName);
        index+=getRoleParameterStartString().length();
        int index2 = roleString.lastIndexOf(getRoleParameterEndString(), index);
        if (index2 == -1)
            throw new RuntimeException("Invalid role string: "+roleString);
        String paramString = roleString.substring(index,index2);
        //StringTokenizer tokenizer = new StringTokenizer()
        return null;
    }
}
