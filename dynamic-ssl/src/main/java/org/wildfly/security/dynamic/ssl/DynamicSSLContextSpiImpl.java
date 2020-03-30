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
package org.wildfly.security.dynamic.ssl;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.ServiceLoader;

// uses ServiceLoader to find implementations of DynamicSSLContextSPI and if then uses it for delegation of ssl contexts
// if no provider for dynamic ssl is found then fallback ssl context is used
final class DynamicSSLContextSpiImpl extends SSLContextSpi {

    private final DynamicSSLContextSPI dynamicSSLContextImpl;
    private final SSLContext configuredDefaultSSLContext;
    private volatile SSLSocketFactory sslSocketFactory;

    DynamicSSLContextSpiImpl(SSLContext fallbackSslContext) throws NoSuchAlgorithmException {
        SSLContext configuredDefaultSSLContextTemp;
        Iterator<DynamicSSLContextSPI> dynamicSSLContextSPIIterator = ServiceLoader.load(DynamicSSLContextSPI.class).iterator();
        if (dynamicSSLContextSPIIterator.hasNext()) {
            dynamicSSLContextImpl = dynamicSSLContextSPIIterator.next();
            configuredDefaultSSLContextTemp = dynamicSSLContextImpl.getConfiguredDefault() == null ? SSLContext.getDefault() : dynamicSSLContextImpl.getConfiguredDefault();
        } else {
            dynamicSSLContextImpl = null;
            configuredDefaultSSLContextTemp = fallbackSslContext;
        }
        this.configuredDefaultSSLContext = configuredDefaultSSLContextTemp;
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) {
        // ignore
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        if (dynamicSSLContextImpl == null) {
            return configuredDefaultSSLContext.getSocketFactory();
        }
        if (sslSocketFactory == null) {
            synchronized (this) {
                if (sslSocketFactory == null) {
                    sslSocketFactory = new DynamicSslSocketFactory(configuredDefaultSSLContext.getSocketFactory(), dynamicSSLContextImpl);
                }
            }
        }
        return sslSocketFactory;
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return this.configuredDefaultSSLContext.getServerSocketFactory();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return this.configuredDefaultSSLContext.createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) throws IllegalStateException {
        if (dynamicSSLContextImpl == null) {
            return configuredDefaultSSLContext.createSSLEngine(host, port);
        }
        try {
            SSLContext sslContext = dynamicSSLContextImpl
                    .getSSLContext(new URI(null, null, host, port, null, null, null));
            if (sslContext == null) {
                throw new IllegalStateException("Received SSLContext from DynamicSSLContextProvider was null");
            }
            return sslContext.createSSLEngine(host, port);
        } catch (URISyntaxException | DynamicSSLContextException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        throw new UnsupportedOperationException("Dynamic SSLContext does not support sessions");
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        throw new UnsupportedOperationException("Dynamic SSLContext does not support sessions");

    }

    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {
        return this.configuredDefaultSSLContext.getSupportedSSLParameters();
    }
}
