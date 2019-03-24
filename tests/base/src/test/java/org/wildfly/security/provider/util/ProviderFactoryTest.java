package org.wildfly.security.provider.util;

import org.junit.Test;

import java.security.Provider;
import java.util.Arrays;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.junit.Assert.assertTrue;

public class ProviderFactoryTest {

    private String[] elytronProviderNames = new String[]{
            "WildFlyElytronPasswordProvider",
            "WildFlyElytronCredentialStoreProvider",
            "WildFlyElytronKeyProvider",
            "WildFlyElytronKeyStoreProvider",
            "WildFlyElytronSaslAnonymousProvider",
            "WildFlyElytronSaslDigestProvider",
            "WildFlyElytronSaslEntityProvider",
            "WildFlyElytronSaslExternalProvider",
            "WildFlyElytronSaslGs2Provider",
            "WildFlyElytronSaslGssapiProvider",
            "WildFlyElytronSaslLocalUserProvider",
            "WildFlyElytronSaslOAuth2Provider",
            "WildFlyElytronSaslOTPProvider",
            "WildFlyElytronSaslPlainProvider",
            "WildFlyElytronSaslScramProvider"
    };

    @Test
    public void findAllElytronProvidersTest() {
        Supplier<Provider[]> supplier = ProviderFactory.getDefaultProviderSupplier(ProviderFactoryTest.class.getClassLoader());
        assertTrue(Arrays.stream(supplier.get())
                .map(Provider::getName)
                .collect(Collectors.toList())
                .containsAll(Arrays.asList(this.elytronProviderNames)));
    }
}
