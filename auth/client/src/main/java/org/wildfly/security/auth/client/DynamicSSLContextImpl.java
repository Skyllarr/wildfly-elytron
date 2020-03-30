package org.wildfly.security.auth.client;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.dynamic.ssl.DynamicSSLContextSPI;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.util.List;

@MetaInfServices(value = DynamicSSLContextSPI.class)
public class DynamicSSLContextImpl implements DynamicSSLContextSPI {

    private SSLContext configuredDefaultSSLContext;
    private final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT =
            AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
    private AuthenticationContext authenticationContext = AuthenticationContext.captureCurrent();
    private List<SSLContext> configuredSSLContexts;

    public DynamicSSLContextImpl() {
        this.configuredSSLContexts = AUTH_CONTEXT_CLIENT.getConfiguredSSLContexts(authenticationContext);
    }

    @Override
    public SSLContext getConfiguredDefault() {
        return this.configuredDefaultSSLContext;
    }

    @Override
    public List<SSLContext> getConfiguredSSLContexts() {
        return this.configuredSSLContexts;
    }

    @Override
    public SSLContext getSSLContext(URI uri) {
        try {
            return AUTH_CONTEXT_CLIENT.getSSLContext(uri, authenticationContext);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }
}
