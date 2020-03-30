/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.auth.client;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.dynamic.ssl.DynamicSSLContextException;
import org.wildfly.security.dynamic.ssl.DynamicSSLContextSPI;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.util.List;

// implementation of dynamic ssl context by elytron client
@MetaInfServices(value = DynamicSSLContextSPI.class)
public class DynamicSSLContextImpl implements DynamicSSLContextSPI {

    private final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT =
            AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
    private AuthenticationContext authenticationContext = AuthenticationContext.captureCurrent();
    private SSLContext configuredDefaultSSLContext;
    private List<SSLContext> configuredSSLContexts;

    public DynamicSSLContextImpl() throws GeneralSecurityException {
        this.configuredSSLContexts = AUTH_CONTEXT_CLIENT.getConfiguredSSLContexts(authenticationContext);
        this.configuredDefaultSSLContext = AUTH_CONTEXT_CLIENT.getDefaultSSLContext(authenticationContext);
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
    public SSLContext getSSLContext(URI uri) throws DynamicSSLContextException {
        try {
            return AUTH_CONTEXT_CLIENT.getSSLContext(uri, authenticationContext);
        } catch (GeneralSecurityException e) {
            throw new DynamicSSLContextException(e);
        }
    }
}
