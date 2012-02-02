/* Copyright (c) 2001 - 2011 TOPP - www.openplans.org.  All rights reserved.
 * This code is licensed under the GPL 2.0 license, availible at the root
 * application directory.
 */
package org.geoserver.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Enumeration;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.geoserver.security.password.RandomPasswordProvider;
import org.geotools.util.logging.Logging;
import org.springframework.beans.factory.BeanNameAware;

/**
 * Class for Geoserver specific key management
 * 
 * <strong>requires a master password</strong> form
 * {@link MasterPasswordProviderImpl}
 * 
 * The type of the keystore is JCEKS and can be used/modified
 * with java tools like "keytool" from the command line.
 *  *  
 * 
 * @author christian
 *
 */
public class KeyStoreProviderImpl implements BeanNameAware, KeyStoreProvider{
    
    public final static String DEFAULT_BEAN_NAME="DefaultKeyStoreProvider";
    public final static String DEFAULT_FILE_NAME="geoserver.jceks";
    public final static String PREPARED_FILE_NAME="geoserver.jceks.new";
    
    public final static String CONFIGPASSWORDKEY = "config:password:key";
    public final static String URLPARAMKEY = "url:param:key";
    public final static String USERGROUP_PREFIX = "ug:";
    public final static String USERGROUP_POSTFIX = ":key";
    
    static protected Logger LOGGER = Logging.getLogger("org.geoserver.security");
    protected String name;
    protected File keyStoreFile;
    protected KeyStore ks;

    GeoServerSecurityManager securityManager;

    public KeyStoreProviderImpl()  {
    }

    @Override
    public void setBeanName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setSecurityManager(GeoServerSecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    public GeoServerSecurityManager getSecurityManager() {
        return securityManager;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getKeyStoreProvderFile()
     */
    @Override
    public File getFile() {
        if (keyStoreFile == null) {
            try {
                keyStoreFile = new File(securityManager.getSecurityRoot(), DEFAULT_FILE_NAME);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return keyStoreFile;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#reloadKeyStore()
     */
    @Override
    public void reloadKeyStore() throws IOException{
        ks=null;
        assertActivatedKeyStore();
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getKey(java.lang.String)
     */
    @Override
    public Key getKey(String alias) throws IOException{
        assertActivatedKeyStore();
        try {
            return ks.getKey(alias,
                securityManager.getMasterPassword().toCharArray());
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getConfigPasswordKey()
     */
    @Override
    public String getConfigPasswordKey() throws IOException{
        SecretKey key = getSecretKey(CONFIGPASSWORDKEY);
        if (key==null) return null;
        return new String(key.getEncoded());
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#hasConfigPasswordKey()
     */
    @Override
    public boolean hasConfigPasswordKey() throws IOException {
        return containsAlias(CONFIGPASSWORDKEY);
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getUrlParamKey()
     */
    @Override
    public String getUrlParamKey() throws IOException{
        SecretKey key = getSecretKey(URLPARAMKEY);
        if (key==null) return null;
        return new String(key.getEncoded());

    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#hasUrlParamKey()
     */
    @Override
    public boolean hasUrlParamKey() throws IOException {
        return containsAlias(URLPARAMKEY);
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#containsAlias(java.lang.String)
     */
    @Override
    public boolean containsAlias(String alias) throws IOException{
        try {
            return ks.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new IOException(e);
        }
    }
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getUserGRoupKey(java.lang.String)
     */
    @Override
    public String getUserGroupKey(String serviceName) throws IOException{
        SecretKey key = getSecretKey(aliasForGroupService(serviceName));
        if (key==null) return null;
        return new String(key.getEncoded());

    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#hasUserGRoupKey(java.lang.String)
     */
    @Override
    public boolean hasUserGroupKey(String serviceName) throws IOException {
        return containsAlias(aliasForGroupService(serviceName));
        
    }

    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getSecretKey(java.lang.String)
     */
    @Override
    public SecretKey getSecretKey(String name) throws IOException{
        Key key = getKey(name);
        if (key==null) return null;
        if ((key instanceof SecretKey) == false)
            throw new IOException("Invalid key type for: "+name);
        return (SecretKey) key;
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getPublicKey(java.lang.String)
     */
    @Override
    public PublicKey getPublicKey(String name) throws IOException{
        Key key = getKey(name);
        if (key==null) return null;
        if ((key instanceof PublicKey) == false)
            throw new IOException("Invalid key type for: "+name);
        return (PublicKey) key;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String name) throws IOException{
        Key key = getKey(name);
        if (key==null) return null;
        if ((key instanceof PrivateKey) == false)
            throw new IOException("Invalid key type for: "+name);
        return (PrivateKey) key;
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#aliasForGroupService(java.lang.String)
     */
    @Override
    public String aliasForGroupService(String serviceName) {
        StringBuffer buff = new StringBuffer(USERGROUP_PREFIX);
        buff.append(serviceName);
        buff.append(USERGROUP_POSTFIX);
        return buff.toString();            
    }
    
    /**
     * Opens or creates a {@link KeyStore} using the file
     * {@link #DEFAULT_FILE_NAME}
     * 
     * Throws an exception for an invalid master key
     * 
     * @throws IOException 
     */            
    protected void assertActivatedKeyStore() throws IOException {
        if (ks != null) 
            return;
        try {
            String masterPassword = securityManager.getMasterPassword();
            ks = KeyStore.getInstance("JCEKS");    
            if (getFile().exists()==false) { // create an empy one
                ks.load(null, masterPassword.toCharArray());
                addInitialKeys();
                FileOutputStream fos = new FileOutputStream(getFile());
                ks.store(fos, masterPassword.toCharArray());            
                fos.close();
            } else {
                FileInputStream fis =
                        new FileInputStream(getFile());
                ks.load(fis, masterPassword.toCharArray());
                fis.close();
            }
        } catch (Exception ex) {
            if (ex instanceof IOException) // avoid useless wrapping
                throw (IOException) ex;
            throw new IOException (ex);
        }            
        
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#isKeystorePassword(java.lang.String)
     */
    @Override
    public boolean isKeyStorePassword(String password) throws IOException{
        if (password==null) return false;
        assertActivatedKeyStore();
        
        KeyStore testStore=null;
        try {
            testStore = KeyStore.getInstance("JCEKS");
        } catch (KeyStoreException e1) {
            // should not happen, see assertActivatedKeyStore
            throw new RuntimeException(e1);
        }
        FileInputStream fis =
                new FileInputStream(getFile());
        try {
            testStore.load(fis, password.toCharArray());
        } catch (IOException e2) {
            // indicates invalid password
            return false;
        } catch (Exception e) {
            // should not happen, see assertActivatedKeyStore
            throw new RuntimeException(e);
        }                
        fis.close();     
        return true;
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#setSecretKey(java.lang.String, java.lang.String)
     */
    @Override
    public void setSecretKey(String alias, String key  ) throws IOException {
        assertActivatedKeyStore();
        SecretKey mySecretKey=new SecretKeySpec(key.getBytes(),"PBE");
        KeyStore.SecretKeyEntry skEntry =
            new KeyStore.SecretKeyEntry(mySecretKey);
        try {
            ks.setEntry(alias, skEntry, 
               new KeyStore.PasswordProtection(securityManager.getMasterPassword().toCharArray()));
        } catch (KeyStoreException e) {
            throw new IOException(e);
        }
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#setUserGroupKey(java.lang.String, java.lang.String)
     */
    @Override
    public void setUserGroupKey(String serviceName,String password) throws IOException{
        String alias = aliasForGroupService(serviceName);
        setSecretKey(alias, password);
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#removeKey(java.lang.String)
     */
    @Override
    public void removeKey(String alias ) throws IOException {
        assertActivatedKeyStore();
        try {
            ks.deleteEntry(alias);
        } catch (KeyStoreException e) {
            throw new IOException(e);
        }
    }

    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#storeKeyStore()
     */
    @Override
    public void storeKeyStore() throws IOException{
        // store away the keystore
        assertActivatedKeyStore();
        FileOutputStream fos = new  FileOutputStream(getFile());
        try {
            ks.store(fos, securityManager.getMasterPassword().toCharArray());
        } catch (Exception e) {
            throw new IOException(e);
        }
        fos.close();
    }
    
    /**
     * Creates initial key entries
     * auto generated keys
     * {@link #CONFIGPASSWORDKEY}
     * {@link #URLPARAMKEY}
     * 
     * @throws IOException
     */
    protected void addInitialKeys() throws IOException {
        String urlKey = RandomPasswordProvider.get().getRandomPassword(32);
        setSecretKey( URLPARAMKEY, urlKey);
        String configPasswordString = RandomPasswordProvider.get().getRandomPassword(32);
        setSecretKey( CONFIGPASSWORDKEY, configPasswordString);
    }
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#prepareForMasterPasswordChange(java.lang.String, java.lang.String)
     */
    @Override
    public void prepareForMasterPasswordChange(String oldPassword,String newPassword) throws IOException{

                
        File dir = getFile().getParentFile();
        File newKSFile = new File(dir,PREPARED_FILE_NAME);
        if (newKSFile.exists())
            newKSFile.delete();
        
        try {
            KeyStore oldKS=KeyStore.getInstance("JCEKS");
            FileInputStream fin = new FileInputStream(getFile());
            oldKS.load(fin, oldPassword.toCharArray());
            fin.close();
            
            KeyStore newKS = KeyStore.getInstance("JCEKS");
            newKS.load(null, newPassword.toCharArray());
            KeyStore.PasswordProtection protectionparam = 
                    new KeyStore.PasswordProtection(newPassword.toCharArray());

            Enumeration<String> enumeration = oldKS.aliases();
            while (enumeration.hasMoreElements()) {
                String alias =enumeration.nextElement();
                Key key = oldKS.getKey(alias, 
                    securityManager.getMasterPassword().toCharArray());
                KeyStore.Entry entry =null;
                if (key instanceof SecretKey) 
                    entry = new KeyStore.SecretKeyEntry((SecretKey)key);
                if (key instanceof PrivateKey) 
                    entry = new KeyStore.PrivateKeyEntry((PrivateKey)key,
                            oldKS.getCertificateChain(alias));                         
                if (key instanceof PublicKey) 
                    entry = new KeyStore.TrustedCertificateEntry(oldKS.getCertificate(alias));                         
                if (entry == null)
                    LOGGER.warning("Unknown key in store, alias: "+alias+
                            " class: "+ key.getClass().getName());
                else
                    newKS.setEntry(alias, entry, protectionparam);
            }            
           FileOutputStream fos = new FileOutputStream(newKSFile);                    
           newKS.store(fos, newPassword.toCharArray());            
           fos.close();
            
        } catch (Exception ex) {
            throw new IOException(ex);
        } 
    }

    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#abortMasterPasswordChange()
     */
    @Override
    public void abortMasterPasswordChange() {
        File dir = getFile().getParentFile();
        File newKSFile = new File(dir,PREPARED_FILE_NAME);
        if (newKSFile.exists())
            newKSFile.delete();
        
    }
    
    
    /* (non-Javadoc)
     * @see org.geoserver.security.password.KeystoreProvider#commitMasterPasswordChange()
     */
    @Override
    public void commitMasterPasswordChange() throws IOException {
        File dir = getFile().getParentFile();
        File newKSFile = new File(dir,PREPARED_FILE_NAME);
        File oldKSFile = new File(dir,DEFAULT_FILE_NAME);
        
        if (newKSFile.exists()==false)
            return; //nothing to do

        if (oldKSFile.exists()==false)
            return; //not initialized
        
        // Try to open with new password
        FileInputStream fin = new FileInputStream(newKSFile);
        try {
            KeyStore newKS = KeyStore.getInstance("JCEKS");            
            newKS.load(fin, securityManager.getMasterPassword().toCharArray());
            
            // to be sure, decrypt all keys
            Enumeration<String> enumeration = newKS.aliases();
            while (enumeration.hasMoreElements()) {
                newKS.getKey(enumeration.nextElement(), 
                    securityManager.getMasterPassword().toCharArray());
            }            
            fin.close();
            fin=null;
            if (oldKSFile.delete()==false) { 
                LOGGER.severe("cannot delete " +getFile().getCanonicalPath());
                return;
            }
            
            if (newKSFile.renameTo(oldKSFile)==false) {
                String msg = "cannot rename "+ newKSFile.getCanonicalPath();
                msg += "to " + oldKSFile.getCanonicalPath();
                msg += "Try to rename manually and restart";
                LOGGER.severe(msg);
                return;
            }
            reloadKeyStore();
            LOGGER.info("Successfully changed master password");            
        } catch (IOException e) {
            String msg = "cannot open new keystore: "+ newKSFile.getCanonicalPath();
            msg+="\ncannot open new keystore: "+ newKSFile.getCanonicalPath();
            msg+="\nIs the new master password activated ? ";
            msg+="\nDetailed message: "+e.getMessage();
            LOGGER.warning(msg);
            throw e;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }        
        finally {
            if (fin != null)
               try{ 
                   fin.close();
                   } 
                catch (IOException ex) {
                    // give up
                }
        }
        
    }
}
