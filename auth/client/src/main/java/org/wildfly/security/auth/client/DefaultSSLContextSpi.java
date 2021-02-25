package org.wildfly.security.auth.client;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.xml.stream.XMLStreamException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DefaultSSLContextSpi extends SSLContextSpi {

    private SSLContext configuredDefaultClientSSLContext;

    public DefaultSSLContextSpi() {
        this.configuredDefaultClientSSLContext = AuthenticationContext.captureCurrent().authRules.getConfiguration().getSslContextForProvider();
    }

    public DefaultSSLContextSpi(String configPath) {
        try {
            AuthenticationContext ac = ElytronXmlParser.parseAuthenticationClientConfiguration(new URI(configPath)).create();
            this.configuredDefaultClientSSLContext = ac.authRules.getConfiguration().getSslContextForProvider();
        } catch (XMLStreamException | URISyntaxException e) {
            e.printStackTrace(); // log problem but ignore
        } catch (GeneralSecurityException e) {
            e.printStackTrace(); // log problem but ignore
        }
    }

    public DefaultSSLContextSpi(AuthenticationConfiguration ac) throws NoSuchAlgorithmException {
        this.configuredDefaultClientSSLContext = ac.getSslContextForProvider();
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
