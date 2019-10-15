package org.wildfly.security.auth.client.spi;

import org.jboss.resteasy.client.jaxrs.spi.ClientConfigException;
import org.jboss.resteasy.client.jaxrs.spi.ClientConfigProvider;
import org.kohsuke.MetaInfServices;
import org.wildfly.security.auth.callback.CredentialCallback;
import org.wildfly.security.auth.client.AuthenticationContext;
import org.wildfly.security.auth.client.AuthenticationContextConfigurationClient;
import org.wildfly.security.credential.BearerTokenCredential;

import javax.net.ssl.SSLContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.net.URI;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;

/**
 * RESTEasy client provider implementation.
 *
 * @author dvilkola@redhat.com
 */
@MetaInfServices(value = ClientConfigProvider.class)
public class RESTEasyClientConfigProviderImpl implements ClientConfigProvider {

   static final AuthenticationContextConfigurationClient AUTH_CONTEXT_CLIENT = AccessController.doPrivileged((PrivilegedAction<AuthenticationContextConfigurationClient>) AuthenticationContextConfigurationClient::new);
   AuthenticationContext authenticationContext = AuthenticationContext.captureCurrent();

   @Override
   public SSLContext getSSLContext(URI uri) throws ClientConfigException {
      try {
         return AUTH_CONTEXT_CLIENT.getSSLContext(uri, authenticationContext);
      } catch (GeneralSecurityException e) {
         throw new ClientConfigException("Unable to obtain SSLContext");
      }
   }

   @Override
   public String getUsername(URI uri) throws ClientConfigException {
      final CallbackHandler callbackHandler = AUTH_CONTEXT_CLIENT.getCallbackHandler(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
      NameCallback nameCallback = new NameCallback("user name");
      try {
         callbackHandler.handle(new Callback[]{nameCallback});
         return nameCallback.getName();
      } catch (IOException | UnsupportedCallbackException e) {
         throw new ClientConfigException("Name callback handling was unsuccessful");
      }
   }

   @Override
   public String getPassword(URI uri) throws ClientConfigException {
      final CallbackHandler callbackHandler = AUTH_CONTEXT_CLIENT.getCallbackHandler(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
      PasswordCallback passwordCallback = new PasswordCallback("password", false);
      try {
         callbackHandler.handle(new Callback[]{passwordCallback});
         char[] password = passwordCallback.getPassword();
         if (password == null) {
            return null;
         }
         return new String(password);
      } catch (IOException | UnsupportedCallbackException e) {
         throw new ClientConfigException("Password callback handling was unsuccessful");
      }
   }

   @Override
   public String getBearerToken(URI uri) throws ClientConfigException {
      final CallbackHandler callbackHandler = AUTH_CONTEXT_CLIENT.getCallbackHandler(AUTH_CONTEXT_CLIENT.getAuthenticationConfiguration(uri, authenticationContext));
      final CredentialCallback credentialCallback = new CredentialCallback(BearerTokenCredential.class);
      try {
         callbackHandler.handle(new Callback[]{credentialCallback});
         BearerTokenCredential token = credentialCallback.getCredential(BearerTokenCredential.class);
         if (token == null) {
            return null;
         }
         return token.getToken();
      } catch (IOException | UnsupportedCallbackException e) {
         throw new ClientConfigException("Password callback handling was unsuccessful");
      }
   }
}
