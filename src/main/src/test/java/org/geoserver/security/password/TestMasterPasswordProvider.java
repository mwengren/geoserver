package org.geoserver.security.password;

import java.io.IOException;

import org.geoserver.security.GeoServerSecurityProvider;
import org.geoserver.security.MasterPasswordProvider;

public final class TestMasterPasswordProvider extends MasterPasswordProvider {

    @Override
    protected String doGetMasterPassword() throws Exception {
        return "geoserver3";
    }

    @Override
    protected void doSetMasterPassword(String passwd) throws Exception {
    }

    public static class Provider extends GeoServerSecurityProvider {
        @Override
        public Class<? extends MasterPasswordProvider> getMasterPasswordProviderClass() {
            return TestMasterPasswordProvider.class;
        }

        @Override
        public MasterPasswordProvider createMasterPasswordProvider(
                MasterPasswordProviderConfig config) throws IOException {
            return new TestMasterPasswordProvider();
        }
    }
}
