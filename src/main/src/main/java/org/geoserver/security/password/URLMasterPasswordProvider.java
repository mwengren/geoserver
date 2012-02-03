/* Copyright (c) 2001 - 2012 TOPP - www.openplans.org.  All rights reserved.
 * This code is licensed under the GPL 2.0 license, available at the root
 * application directory.
 */
package org.geoserver.security.password;

import static org.geoserver.security.password.URLMasterPasswordProviderException.*;
import static org.geoserver.security.SecurityUtils.toBytes;
import static org.geoserver.security.SecurityUtils.toChars;
import static org.geoserver.security.SecurityUtils.scramble;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;

import org.apache.commons.io.IOUtils;
import org.geoserver.config.util.XStreamPersister;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerSecurityProvider;
import org.geoserver.security.MasterPasswordProvider;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.validation.SecurityConfigException;
import org.geoserver.security.validation.SecurityConfigValidator;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

/**
 * Master password provider that retrieves and optionally stores the master password from a url.
 * 
 * @author Justin Deoliveira, OpenGeo
 */
public final class URLMasterPasswordProvider extends MasterPasswordProvider {

    /** base encryption key */
    static final char[] BASE = new char[]{ 'a', 'f', '8', 'd', 'f', 's', 's', 'v', 'j', 'K', 'L', 
        '0', 'I', 'H', '(', 'a', 'd', 'f', '2', 's', '0', '0', 'd', 's', '9', 'f', '2', 'o', 'f', 
        '(', '4', ']' };

    /** permutation indicies */
    static final int[] PERM = new int[]{25, 10, 5, 21, 14, 27, 23, 4, 3, 31, 16, 29, 20, 11, 0, 26,
        24, 22, 13, 12, 1, 8, 18, 19, 7, 2, 17, 6, 9, 28, 30, 15};
    
    URLMasterPasswordProviderConfig config;

    @Override
    public void initializeFromConfig(SecurityNamedServiceConfig config)
            throws IOException {
        super.initializeFromConfig(config);
        this.config = (URLMasterPasswordProviderConfig)config; 
    }

    @Override
    protected char[] doGetMasterPassword() throws Exception {
        try {
            InputStream in = input(config.getURL(), getConfigDir());
            try {
                return toChars(decode(IOUtils.toByteArray(in)));
            }
            finally {
                in.close();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void doSetMasterPassword(char[] passwd) throws Exception {
        OutputStream out = output(config.getURL(), getConfigDir());
        try {
            out.write(encode(passwd));
        }
        finally {
            out.close();
        }
    }

    File getConfigDir() throws IOException {
        return new File(getSecurityManager().getMasterPasswordProviderRoot(), getName());
    }

    byte[] encode(char[] passwd) {
        
        if (!config.isEncrypting()) {
            return toBytes(passwd);
        }

        //encrypt the password
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();

        char[] key = key();
        try {
            encryptor.setPasswordCharArray(key);
            return encryptor.encrypt(toBytes(passwd));
        }
        finally {
            scramble(key);
        }
    }

    byte[] decode(byte[] passwd) {
        if (!config.isEncrypting()) {
            return passwd;
        }

        //decrypt the password
        StandardPBEByteEncryptor encryptor = new StandardPBEByteEncryptor();
        char[] key = key();
        try {
            encryptor.setPasswordCharArray(key);
            return encryptor.decrypt(passwd);
        }
        finally {
            scramble(key);
        }

    }

    char[] key() {
        //generate the key
        char[] key = BASE.clone();
        for (int i = 0; i < 256; i++) {
            int j = i % key.length;

            //swap char at j with char at PERM[j]
            char c = key[j];
            key[j] = key[PERM[j]];
            key[PERM[j]] = c;
        }

        return key;
    }

    static OutputStream output(URL url, File configDir) throws IOException {
        //check for file url
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            File f = new File(url.getFile());
            if (!f.isAbsolute()) {
                //make relative to config dir
                f = new File(configDir, f.getPath());
            }
            return new FileOutputStream(f);
        }
        else {
            URLConnection cx = url.openConnection();
            cx.setDoOutput(true);
            return cx.getOutputStream();
        }
    }

    static InputStream input(URL url, File configDir) throws IOException {
        //check for a file url
        if ("file".equalsIgnoreCase(url.getProtocol())) {
            File f = new File(url.getFile());
            //check if the file is relative
            if (!f.isAbsolute()) {
                //make it relative to the config directory for this password provider
                f = new File(configDir, f.getPath());
            }
            return new FileInputStream(f);
        }
        else {
            return url.openStream();
        }
    }

    static class URLMasterPasswordProviderValidator extends SecurityConfigValidator {

        public URLMasterPasswordProviderValidator(GeoServerSecurityManager securityManager) {
            super(securityManager);
        }

        @Override
        public void validate(MasterPasswordProviderConfig config)
                throws SecurityConfigException {
            super.validate(config);
            
            URLMasterPasswordProviderConfig urlConfig = (URLMasterPasswordProviderConfig) config;
            URL url = urlConfig.getURL();

            if (url == null) {
                throw new URLMasterPasswordProviderException(URL_REQUIRED);
            }

            if (config.isReadOnly()) {
                //read-only, assure we can read from url
                try {
                    InputStream in = input(url, 
                        new File(manager.getMasterPasswordProviderRoot(), config.getName()));
                    try {
                        in.read();
                    }
                    finally {
                        in.close();
                    }
                } catch (IOException ex) {
                    throw new URLMasterPasswordProviderException(URL_LOCATION_NOT_READABLE, url);
                }
            }
        }
    }

    public static class SecurityProvider extends GeoServerSecurityProvider {
        @Override
        public void configure(XStreamPersister xp) {
            super.configure(xp);
            xp.getXStream().alias("urlProvider", URLMasterPasswordProviderConfig.class);
        }
        
        @Override
        public Class<? extends MasterPasswordProvider> getMasterPasswordProviderClass() {
            return URLMasterPasswordProvider.class;
        }
 
        @Override
        public MasterPasswordProvider createMasterPasswordProvider(
            MasterPasswordProviderConfig config) throws IOException {
            return new URLMasterPasswordProvider();
        }

        @Override
        public SecurityConfigValidator createConfigurationValidator(
                GeoServerSecurityManager securityManager) {
            return new URLMasterPasswordProviderValidator(securityManager);
        }
    }

}
