/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2021 Red Hat, Inc., and individual contributors
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

import org.wildfly.client.config.ConfigXMLParseException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;

/**
 * SSLContextSpi that is used by ElytronClientDefaultSSLContextProvider
 */
public class DefaultSSLContextSpi extends SSLContextSpi {

    private SSLContext configuredDefaultClientSSLContext;

    public DefaultSSLContextSpi() throws GeneralSecurityException {
        this(AuthenticationContext.captureCurrent());
    }

    public DefaultSSLContextSpi(String configPath) throws GeneralSecurityException, URISyntaxException, ConfigXMLParseException {
        this(ElytronXmlParser.parseAuthenticationClientConfiguration(new URI(configPath)).create());
    }

    public DefaultSSLContextSpi(AuthenticationContext authenticationContext) throws GeneralSecurityException {
        AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT = AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
        this.configuredDefaultClientSSLContext = AUTH_CONTEXT_CLIENT.getSSLContext(authenticationContext);
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) {
        // ignore
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return this.configuredDefaultClientSSLContext.getSocketFactory();
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return this.configuredDefaultClientSSLContext.getServerSocketFactory();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return this.configuredDefaultClientSSLContext.createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String s, int i) {
        return this.configuredDefaultClientSSLContext.createSSLEngine(s, i);
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return this.configuredDefaultClientSSLContext.getServerSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return this.configuredDefaultClientSSLContext.getClientSessionContext();
    }

}
