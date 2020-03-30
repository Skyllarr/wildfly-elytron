package org.wildfly.security.dynamic.ssl;

import javax.net.ssl.SSLContext;
import java.security.Provider;

public final class DynamicSSLContext extends SSLContext {

    public DynamicSSLContext(DynamicSslContextSpi contextSpi, Provider provider, String protocol) {
        super(contextSpi, provider, protocol);
    }

    public DynamicSSLContext(SSLContext configuredDefaultSSLContext) throws Exception {

        super(new DynamicSslContextSpi(configuredDefaultSSLContext), null, null);
    }
}
