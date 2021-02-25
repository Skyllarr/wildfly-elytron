package org.wildfly.security.auth.client;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.List;
import java.util.Map;

public final class ClientSSLContextProvider extends Provider {

    public ClientSSLContextProvider() {
        super("ClientSSLContextProvider", 1.0, "Elytron client provider for default SSLContext");
        putService(new ClientSSLContextProviderService(this, "SSLContext",
                "Default", "org.wildfly.security.auth.client.ClientSSLContextProvider", null, null,
                null));
    }

    public ClientSSLContextProvider(String configPath) {
        super("ClientSSLContextProvider", 1.0, "Elytron client provider for default SSLContext");
        putService(new ClientSSLContextProviderService(this, "SSLContext",
                "Default", "org.wildfly.security.auth.client.DefaultSSLContextSpi", null, null,
                configPath)); // new DefaultSSLContextSpi(configPath.toString());
    }

    private static final class ClientSSLContextProviderService extends Provider.Service {
        String configPath;

        ClientSSLContextProviderService(Provider provider, String type, String algorithm, String className, List<String> aliases,
                                        Map<String, String> attributes, String configPath) {
            super(provider, type, algorithm, className, aliases, attributes);
            this.configPath = configPath;
        }

        @Override
        public Object newInstance(Object ignored) throws NoSuchAlgorithmException {
            RuleNode<AuthenticationConfiguration> authRules = AuthenticationContext.captureCurrent().authRules;
            if (configPath == null && authRules != null) {
                return new DefaultSSLContextSpi(authRules.getConfiguration());
            } else {
                return new DefaultSSLContextSpi(this.configPath);
            }
        }
    }
}
