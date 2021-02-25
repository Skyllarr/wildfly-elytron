package org.wildfly.security.auth.client;

import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

public class ClientSSLContextProviderTest {

    @Test
    public void test() throws GeneralSecurityException, IOException {
        SSLContext sslC = sslContext("/home/skylar/work/projects/wildfly-elytron/auth/client/src/test/resources/client.keystore", "password");
        AuthenticationConfiguration ac = AuthenticationConfiguration.empty().useSSLContextForProvider(sslC);
        AuthenticationContext context = AuthenticationContext.empty();
        context = context.with(MatchRule.ALL, ac);
        context.run(() -> {
            Provider p =new ClientSSLContextProvider();
            Security.insertProviderAt(p, 1);
            Assert.assertEquals("ClientSSLContextProvider", Security.getProvider("ClientSSLContextProvider").getName());
            SSLContext cip = null;
            try {
                cip = SSLContext.getDefault();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                Assert.fail();
            }
            Assert.assertEquals(cip.getProvider().getName(), "ClientSSLContextProvider");
            Assert.assertNotNull(cip);
        });
    }

    @Test
    public void test2() throws GeneralSecurityException, IOException {
//        Security.insertProviderAt(new ClientSSLContextProvider("/home/skylar/work/projects/wildfly-elytron/auth/client/src/test/resources/client.keystore"), 1);
        SSLContext sslC = sslContext("/home/skylar/work/projects/wildfly-elytron/auth/client/src/test/resources/client.keystore", "password");
        AuthenticationConfiguration ac = AuthenticationConfiguration.empty().useSSLContextForProvider(sslC);
        AuthenticationContext context = AuthenticationContext.empty();
        context = context.with(MatchRule.ALL, ac);
        context.run(() -> {
            Provider p =new ClientSSLContextProvider("file:/home/skylar/work/projects/wildfly-elytron/auth/client/src/test/resources/org/wildfly/security/auth/client/test-wildfly-config-v1_7.xml");
            Security.insertProviderAt(p, 1);
            Assert.assertEquals("ClientSSLContextProvider", Security.getProvider("ClientSSLContextProvider").getName());
            SSLContext cip = null;
            try {
                cip = SSLContext.getDefault();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                Assert.fail();
            }
            Assert.assertEquals(cip.getProvider().getName(), "ClientSSLContextProvider");
            Assert.assertNotNull(cip);
        });
    }

    private static SSLContext sslContext(String keystoreFile, String password)
            throws GeneralSecurityException, IOException {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = new FileInputStream(keystoreFile)) {
            keystore.load(in, password.toCharArray());
        }
        KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keystore, password.toCharArray());

        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keystore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory.getTrustManagers(),
                new SecureRandom());

        return sslContext;
    }

}
