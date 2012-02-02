package org.geoserver.security.password;

import static org.geoserver.security.GeoServerSecurityManager.MASTER_PASSWD_DEFAULT;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.geoserver.security.GeoServerSecurityTestSupport;
import org.geoserver.security.validation.MasterPasswordChangeException;

public class MasterPasswordChangeTest extends GeoServerSecurityTestSupport {

    @Override
    protected void setUpInternal() throws Exception {
        super.setUpInternal();
        applicationContext.getBeanFactory()
            .registerSingleton("testMasterPasswordProvider", new TestMasterPasswordProvider());
    }

    @Override
    protected String[] getSpringContextLocations() {
        List<String> list = new ArrayList<String>(Arrays.asList(super.getSpringContextLocations()));
        list.add(getClass().getResource(getClass().getSimpleName() + "-context.xml").toString());
        return list.toArray(new String[list.size()]);
    }

    public void testMasterPasswordChange() throws Exception {
        // keytool -storepasswd -new geoserver1 -storepass geoserver -storetype jceks -keystore geoserver.jks
        
        assertEquals(MASTER_PASSWD_DEFAULT, getMasterPassword());
        MasterPasswordConfig config = getSecurityManager().getMasterPasswordConfig();
        
        URLMasterPasswordProviderConfig mpConfig = (URLMasterPasswordProviderConfig) 
            getSecurityManager().loadMasterPassswordProviderConfig(config.getProviderName());
        
        assertTrue(mpConfig.getURL().toString().endsWith(URLMasterPasswordProviderConfig.MASTER_PASSWD_FILENAME));
        getSecurityManager().getKeyStoreProvider().reloadKeyStore();
        
        try {
            getSecurityManager().saveMasterPasswordConfig(config, null, null, null);
            fail();
        } catch (MasterPasswordChangeException ex) {
        }
        
        ///// First change using rw_url
        mpConfig = new URLMasterPasswordProviderConfig();
        mpConfig.setName("rw");
        mpConfig.setClassName(URLMasterPasswordProvider.class.getCanonicalName());
        mpConfig.setReadOnly(false);

        File tmp = new File(getSecurityManager().getSecurityRoot(),"mpw1.properties");
        mpConfig.setURL(tmp.toURI().toURL());
        getSecurityManager().saveMasterPasswordProviderConfig(mpConfig);
        
        config = getSecurityManager().getMasterPasswordConfig();
        config.setProviderName(mpConfig.getName());
        getSecurityManager().saveMasterPasswordConfig(config, MASTER_PASSWD_DEFAULT, "geoserver1", "geoserver1");
        assertEquals("geoserver1", getMasterPassword());
        
        getSecurityManager().getKeyStoreProvider().getConfigPasswordKey();
        
        /////////////// change with ro url
        mpConfig = new URLMasterPasswordProviderConfig();
        mpConfig.setName("ro");
        mpConfig.setClassName(URLMasterPasswordProvider.class.getCanonicalName());
        mpConfig.setReadOnly(true);
        
        tmp = new File(getSecurityManager().getSecurityRoot(),"mpw2.properties");
        mpConfig.setURL(tmp.toURI().toURL());
        
        FileUtils.writeStringToFile(tmp, "geoserver2");
        
        getSecurityManager().saveMasterPasswordProviderConfig(mpConfig);
        config = getSecurityManager().getMasterPasswordConfig();
        config.setProviderName("ro");
        
        getSecurityManager().saveMasterPasswordConfig(config, "geoserver1", null, "geoserver2");
        
        assertEquals("geoserver2",getMasterPassword());
        getSecurityManager().getKeyStoreProvider().getConfigPasswordKey();
        
        /////////////////////// change simulating spring injection
        MasterPasswordProviderConfig mpConfig2 = new MasterPasswordProviderConfig();
        mpConfig2.setName("test");
        mpConfig2.setClassName(TestMasterPasswordProvider.class.getCanonicalName());
        getSecurityManager().saveMasterPasswordProviderConfig(mpConfig2);
        
        config =getSecurityManager().getMasterPasswordConfig();
        config.setProviderName("test");
        getSecurityManager().saveMasterPasswordConfig(config, "geoserver2", "geoserver3", "geoserver3");
        
        // now, a geoserver restart should appear, simulate with
        getSecurityManager().getKeyStoreProvider().commitMasterPasswordChange();

        //////////
        assertEquals("geoserver3",getMasterPassword());
        getSecurityManager().getKeyStoreProvider().getConfigPasswordKey();
    }
}
