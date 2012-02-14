/* Copyright (c) 2001 - 2007 TOPP - www.openplans.org. All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */
package org.geoserver.security.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;

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
    
    protected List<String> splitString(String theString, String delim) {
                
        List<String> result = new ArrayList<String>();
        int startIndex = 0;
        while (true) {
            int index = theString.indexOf(delim,startIndex);
            if (index==-1) {
                result.add(theString.substring(startIndex));
                break;
            } else {
                result.add(theString.substring(startIndex,index));
                index+=delim.length();
            }
            
        }
        return result;        
    }
    
    public GeoServerRole convertRoleFromString(String roleString, String userName) {
        
        List<String> working = splitString(roleString,getRoleParameterStartString());
        GeoServerRole result= new GeoServerRole(working.get(0));
        result.setUserName(userName);
        
        if (working.size()==1) {
            return result;
        }
        
        int index = working.get(1).lastIndexOf(getRoleParameterEndString());
        String roleParamString = working.get(1).substring(0, index);
        working = splitString(roleParamString,getRoleParameterDelimiterString());
        for (String kvp : working) {
            List<String> tmp = splitString(kvp, getRoleParameterAssignmentString());
            result.getProperties().put(tmp.get(0), tmp.get(1));
        }
       return result; 
    }
}
