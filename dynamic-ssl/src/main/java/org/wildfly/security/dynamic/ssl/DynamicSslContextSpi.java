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
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Objects;
import java.util.ServiceLoader;

public final class DynamicSslContextSpi extends SSLContextSpi {

    private final DynamicSSLContextSPI dynamicSSLContextImpl;
    private final SSLContext configuredDefaultSSLContext;
    private volatile SSLSocketFactory sslSocketFactory;

    public DynamicSslContextSpi(final SSLContext configuredDefaultSSLContext) throws Exception{
        Objects.requireNonNull(configuredDefaultSSLContext);
        this.configuredDefaultSSLContext = configuredDefaultSSLContext;
        Iterator<DynamicSSLContextSPI> dynamicSSLContextSPIIterator = ServiceLoader.load(DynamicSSLContextSPI.class).iterator();
        if(dynamicSSLContextSPIIterator.hasNext()) {
            dynamicSSLContextImpl = dynamicSSLContextSPIIterator.next();
        } else {
            throw new Exception("DynamicSslContextSpi provider must be available");
        }
    }

    @Override
    protected void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom secureRandom) {
        // ignore
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
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
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        try {
            return dynamicSSLContextImpl
                    .getSSLContext(new URI(null, null, host, port, null, null, null))
                    .createSSLEngine(host, port);
        } catch (URISyntaxException e) {
            e.printStackTrace();
            return null;
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
