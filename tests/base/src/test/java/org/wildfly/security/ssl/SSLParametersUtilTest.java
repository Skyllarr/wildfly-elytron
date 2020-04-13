package org.wildfly.security.ssl;

import org.junit.Test;
import org.wildfly.security.ssl._private.SSLParametersUtil;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIMatcher;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLParameters;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class SSLParametersUtilTest {

    @Test
    public void tests() {
        SSLParameters params = new SSLParameters();
        String[] cipherSuites = new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA256", "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"};
        String[] protocols = new String[]{"TLSv1.2"};
        String[] passedCipherSuites = cipherSuites.clone();
        String[] passedProtocols = protocols.clone();
        List<SNIServerName> serverNames =  Collections.unmodifiableList(Arrays.asList(new SNIHostName("localhost")));
        List<SNIMatcher> sniMatchers = Collections.unmodifiableList(Arrays.asList(SNIHostName.createSNIMatcher("www\\.example\\.com")));
        final AlgorithmConstraints algorithmConstraints = new AlgorithmConstraints() {
            @Override
            public boolean permits(Set<CryptoPrimitive> set, String s, AlgorithmParameters algorithmParameters) {
                return false;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> set, Key key) {
                return false;
            }

            @Override
            public boolean permits(Set<CryptoPrimitive> set, String s, Key key, AlgorithmParameters algorithmParameters) {
                return false;
            }
        };
        params.setServerNames(serverNames);
        params.setCipherSuites(passedCipherSuites);
        params.setProtocols(passedProtocols);
        params.setSNIMatchers(sniMatchers);
        params.setAlgorithmConstraints(algorithmConstraints);
        params.setWantClientAuth(false);
        params.setNeedClientAuth(true);
        params.setUseCipherSuitesOrder(true);
        params.setEndpointIdentificationAlgorithm("HTTPS");

        SSLParameters copiedSSLParams = SSLParametersUtil.copySSLParameters(params);

        assertNotSame(copiedSSLParams, params);
        assertTrue(copiedSSLParams.getServerNames() != serverNames && copiedSSLParams.getServerNames().equals(serverNames));
        assertTrue(copiedSSLParams.getCipherSuites() != passedCipherSuites && Arrays.equals(copiedSSLParams.getCipherSuites(), cipherSuites));
        assertTrue(copiedSSLParams.getProtocols() != passedProtocols && Arrays.equals(copiedSSLParams.getProtocols(), protocols));
        assertTrue(copiedSSLParams.getSNIMatchers() != sniMatchers && copiedSSLParams.getSNIMatchers().equals(sniMatchers));
        assertSame(copiedSSLParams.getAlgorithmConstraints(), algorithmConstraints);
        assertFalse(copiedSSLParams.getWantClientAuth());
        assertTrue(copiedSSLParams.getNeedClientAuth());
        assertTrue(copiedSSLParams.getUseCipherSuitesOrder());
        assertEquals("HTTPS", copiedSSLParams.getEndpointIdentificationAlgorithm());
    }
}
