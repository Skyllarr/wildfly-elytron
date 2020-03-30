package org.wildfly.security.auth.client;

import org.junit.Assert;
import org.junit.Test;
import org.wildfly.security.dynamic.ssl.DynamicSSLContext;
import org.wildfly.security.dynamic.ssl.DynamicSslContextSpi;
import org.wildfly.security.SecurityFactory;
import org.wildfly.security.auth.client.mocks.MockSSLContext;
import org.wildfly.security.auth.client.mocks.MockSSLContextSPI;
import org.wildfly.security.auth.client.mocks.MockSSLSocketFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.security.GeneralSecurityException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DynamicSSLContextIntersectionTest {

    @Test
    public void testIntersectionOfSupportedCipherSuites() throws GeneralSecurityException {

        SSLSocketFactory sslSocketFactory0Ciphers = new MockSSLSocketFactory() {
            @Override
            public String[] getSupportedCipherSuites() {
                return new String[0];
            }
        };

        SSLSocketFactory sslSocketFactory3Ciphers = new MockSSLSocketFactory() {
            @Override
            public String[] getSupportedCipherSuites() {
                return new String[]{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_CIPHER_SUITE_NOT_COMMON"};
            }
        };

        SSLSocketFactory sslSocketFactory4Ciphers = new MockSSLSocketFactory() {
            @Override
            public String[] getSupportedCipherSuites() {
                return new String[]{"TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_8_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_128_CCM_SHA256"};
            }
        };

        SSLContext sslContext0Ciphers = new MockSSLContext(new MockSSLContextSPI() {
            @Override
            protected SSLSocketFactory engineGetSocketFactory() {
                return sslSocketFactory0Ciphers;
            }
        });

        SSLContext sslContext3Ciphers = new MockSSLContext(new MockSSLContextSPI() {
            @Override
            protected SSLSocketFactory engineGetSocketFactory() {
                return sslSocketFactory3Ciphers;
            }
        });

        SSLContext sslContext4Ciphers = new MockSSLContext(new MockSSLContextSPI() {
            @Override
            protected SSLSocketFactory engineGetSocketFactory() {
                return sslSocketFactory4Ciphers;
            }
        });


        SecurityFactory<SSLContext> sslContextSecurityFactory0Ciphers = mock(SecurityFactory.class);
        SecurityFactory<SSLContext> sslContextSecurityFactoryt3Ciphers = mock(SecurityFactory.class);
        SecurityFactory<SSLContext> sslContextSecurityFactory4Ciphers = mock(SecurityFactory.class);

        when(sslContextSecurityFactory0Ciphers.create()).thenReturn(sslContext0Ciphers);
        when(sslContextSecurityFactoryt3Ciphers.create()).thenReturn(sslContext3Ciphers);
        when(sslContextSecurityFactory4Ciphers.create()).thenReturn(sslContext4Ciphers);

        AuthenticationContext ctx = AuthenticationContext.empty()
                .withSsl(MatchRule.ALL.matchHost("host1"), sslContextSecurityFactory4Ciphers)
                .withSsl(MatchRule.ALL.matchHost("host2"), sslContextSecurityFactoryt3Ciphers);
        ctx.run(checkResultIntersectionSizeIs(2));
        ctx = AuthenticationContext.empty()
                .withSsl(MatchRule.ALL.matchHost("host1"), sslContextSecurityFactory4Ciphers)
                .withSsl(MatchRule.ALL.matchHost("host2"), sslContextSecurityFactoryt3Ciphers)
                .withSsl(MatchRule.ALL.matchHost("host3"), sslContextSecurityFactory0Ciphers);
        ctx.run(checkResultIntersectionSizeIs(0));
        ctx = AuthenticationContext.empty()
                .withSsl(MatchRule.ALL.matchHost("host3"), sslContextSecurityFactory0Ciphers)
                .withSsl(MatchRule.ALL.matchHost("host3"), sslContextSecurityFactory0Ciphers);
        ctx.run(checkResultIntersectionSizeIs(0));
        ctx = AuthenticationContext.empty()
                .withSsl(MatchRule.ALL.matchHost("host1"), sslContextSecurityFactory4Ciphers)
                .withSsl(MatchRule.ALL.matchHost("host1"), sslContextSecurityFactory4Ciphers);
        ctx.run(checkResultIntersectionSizeIs(4));
    }

    private Runnable checkResultIntersectionSizeIs(int intersectionSize) {
        return () -> {
            try {
                DynamicSslContextSpi dynamicSslContextSpi = new DynamicSslContextSpi(SSLContext.getDefault());
                SSLContext dynamicSSLContext = new DynamicSSLContext(dynamicSslContextSpi, null, null);
                Assert.assertEquals(dynamicSSLContext.getSocketFactory().getSupportedCipherSuites().length, intersectionSize);
            } catch (Exception e) {
                e.printStackTrace();
                Assert.fail();
            }
        };
    }
}
