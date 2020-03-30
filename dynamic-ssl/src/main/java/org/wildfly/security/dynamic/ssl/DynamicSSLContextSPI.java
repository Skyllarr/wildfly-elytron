package org.wildfly.security.dynamic.ssl;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.util.List;

public interface DynamicSSLContextSPI {

    SSLContext getConfiguredDefault();
    List<SSLContext> getConfiguredSSLContexts();
    SSLContext getSSLContext(URI uri);
}
