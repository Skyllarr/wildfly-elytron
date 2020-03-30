package org.wildfly.security.auth.client.mocks;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;

public class MockSSLContext extends SSLContext {
    public MockSSLContext(final SSLContextSpi mockContextSpi) {
        super(mockContextSpi, null, null);
    }
}
