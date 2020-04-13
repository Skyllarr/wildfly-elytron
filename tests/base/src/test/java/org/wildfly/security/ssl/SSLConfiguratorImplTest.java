package org.wildfly.security.ssl;

import org.junit.Test;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

public class SSLConfiguratorImplTest {

    @Test
    public void test() throws GeneralSecurityException, IOException {
        SSLContext sslContext = new SSLContextBuilder().build().create();
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        SSLParameters params = socket.getSSLParameters();
        String[] cipherSuites = {"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"};
        String[] protocols = {"TLSv1.3"};
        List<SNIServerName> serverNames =  Arrays.asList(new SNIHostName("localhost"));
        List<SNIMatcher> sniMatchers = Arrays.asList(SNIHostName.createSNIMatcher("www\\.example\\.com"));

        params.setCipherSuites(cipherSuites);
        params.setProtocols(protocols);
        params.setServerNames(serverNames);
        params.setSNIMatchers(sniMatchers);
        params.setWantClientAuth(false);
        params.setNeedClientAuth(true);
        params.setUseCipherSuitesOrder(true);
        params.setEndpointIdentificationAlgorithm("HTTPS");

        socket.setSSLParameters(params);

        assertNotSame(socket.getSSLParameters(), params);
        assertTrue(Arrays.equals(socket.getSSLParameters().getCipherSuites(), cipherSuites));
        assertTrue(Arrays.equals(socket.getSSLParameters().getProtocols(), protocols));
        assertTrue(socket.getSSLParameters().getServerNames() != serverNames && socket.getSSLParameters().getServerNames().equals(serverNames));
        assertTrue(socket.getSSLParameters().getSNIMatchers() != sniMatchers && socket.getSSLParameters().getSNIMatchers().equals(sniMatchers));
        assertFalse(socket.getSSLParameters().getWantClientAuth());
        assertTrue(socket.getSSLParameters().getNeedClientAuth());
        assertTrue(socket.getSSLParameters().getUseCipherSuitesOrder());
        assertEquals("HTTPS", socket.getSSLParameters().getEndpointIdentificationAlgorithm());
    }

    @Test
    public void testRejectNonExistentCipherSuite() throws GeneralSecurityException, IOException {
        SSLContext sslContext = new SSLContextBuilder().build().create();
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        SSLParameters params = socket.getSSLParameters();
        params.setCipherSuites(new String[]{"invalidCipherSuite", "TLS_RSA_WITH_AES_128_CBC_SHA"});
        socket.setSSLParameters(params);
        assertTrue(socket.getSSLParameters().getCipherSuites().length == 1 && socket.getSSLParameters().getCipherSuites()[0].equals("TLS_RSA_WITH_AES_128_CBC_SHA"));
    }

    @Test
    public void testRejectNonExistentProtocol() throws GeneralSecurityException, IOException {
        SSLContext sslContext = new SSLContextBuilder().build().create();
        SSLSocket socket = (SSLSocket) sslContext.getSocketFactory().createSocket();
        SSLParameters params = socket.getSSLParameters();
        List<String> protocols = Arrays.asList(params.getProtocols());
        assertTrue(protocols.contains("TLSv1.2") && protocols.contains("TLSv1.3"));
        params.setProtocols(new String[]{"invalidProtocol", "TLSv1.3"});
        socket.setSSLParameters(params);
        assertTrue(socket.getSSLParameters().getProtocols().length == 1 && socket.getSSLParameters().getProtocols()[0].equals("TLSv1.3"));
    }

}
