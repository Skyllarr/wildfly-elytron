package org.wildfly.security.dynamic.ssl;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.ElytronXmlParser;
import org.wildfly.security.auth.client.InvalidAuthenticationConfigurationException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.PrivilegedAction;
import java.util.ServiceLoader;

import static java.security.AccessController.doPrivileged;

public class DynamicSSLContextTest {
    public static final String RESOURCES = "src/test/resources/org/wildfly/security/dynamic/ssl/";

    @Test
    public void testServer() {
        new SSLServerSocketTestInstance(RESOURCES + "server1.keystore.jks", RESOURCES + "server1.truststore.jks", 10000).run();
        new SSLServerSocketTestInstance(RESOURCES + "server2.keystore.jks", RESOURCES + "server2.truststore.jks", 20000).run();
        new SSLServerSocketTestInstance(RESOURCES + "server3.keystore.jks", RESOURCES + "server3.truststore.jks", 30000).run();

        AuthenticationContext context = doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
            try {
                URL config = getClass().getResource("wildfly-config-dynamic-ssl-test.xml");
                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
            } catch (Throwable t) {
                throw new InvalidAuthenticationConfigurationException(t);
            }
        });
        context.run(() -> {
            if (ServiceLoader.load(DynamicSSLContextSPI.class).iterator().hasNext()) {
                try {
                    SSLContext dynamicSSLContext = new DynamicSSLContext(SSLContext.getDefault());
                    SSLSocketFactory dynamicSSLContextSocketFactory = dynamicSSLContext.getSocketFactory();

                    SSLSocket clientSslSocket1 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("127.0.0.1", 10000);
                    checkOutputIsOK(clientSslSocket1);
                    clientSslSocket1.close();

                    SSLSocket clientSslSocket2 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("localhost", 20000);
                    checkOutputIsOK(clientSslSocket2);
                    clientSslSocket2.close();

                    SSLSocket clientSslSocket3 = (SSLSocket) dynamicSSLContextSocketFactory.createSocket("127.0.0.1", 30000);
                    checkOutputIsOK(clientSslSocket3);
                    clientSslSocket3.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    Assert.fail();
                }
            } else {
                Assert.fail("Dynamic ssl provider not found");
            }
        });
    }

    private void checkOutputIsOK(SSLSocket clientSslSocket) throws IOException {
        clientSslSocket.startHandshake();
        InputStream inputStream = clientSslSocket.getInputStream();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        String line = bufferedReader.readLine().trim();
        Assert.assertEquals("HTTP/1.1 200", line);
        System.out.println("Received from server: " + line);
    }
}
