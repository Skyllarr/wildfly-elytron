package org.wildfly.security.auth.client;

//import org.jboss.arquillian.container.test.api.ContainerController;
//import org.jboss.arquillian.container.test.api.Deployer;
//import org.jboss.arquillian.container.test.api.Deployment;
//import org.jboss.arquillian.container.test.api.RunAsClient;
//import org.jboss.arquillian.container.test.api.TargetsContainer;
//import org.jboss.arquillian.junit.Arquillian;
//import org.jboss.arquillian.test.api.ArquillianResource;
//import org.jboss.shrinkwrap.api.Archive;
//import org.jboss.shrinkwrap.api.ShrinkWrap;
//import org.jboss.shrinkwrap.api.spec.WebArchive;
//import org.junit.Assert;
//import org.junit.Test;
//import org.junit.runner.RunWith;
//import org.wildfly.extras.creaper.core.ManagementClient;
//import org.wildfly.extras.creaper.core.online.ModelNodeResult;
//import org.wildfly.extras.creaper.core.online.OnlineManagementClient;
//import org.wildfly.extras.creaper.core.online.OnlineOptions;
//import org.wildfly.extras.creaper.core.online.operations.admin.Administration;
//
//import javax.net.dynamic.SSLContext;
//import javax.ws.rs.client.Client;
//import javax.ws.rs.client.ClientBuilder;
//import java.io.File;
//import java.io.IOException;
//import java.net.URL;
//import java.security.PrivilegedAction;
//
//import static java.security.AccessController.doPrivileged;

//@RunWith(Arquillian.class)
public class TempDynamicSSLContextSpiTest {

//    private static final String PASSWORD = "secret";
//    private static final String RESOURCES = "src/test/resources/org/wildfly/security/auth/client/";
//    private static final String MUTUALSSLSERVERKEYSTORE = "serverSSL.keystore.jks";
//    private static final String MUTUALSSLSERVERTRUSTSTORE = "serverSSL.truststore.jks";
//    private static final String MUTUALSSLSERVERKEYSTORE2 = "serverSSL2.keystore.jks";
//    private static final String MUTUALSSLSERVERTRUSTSTORE2 = "serverSSL2.truststore.jks";
//    private static final String MUTUALSSLSERVERKEYSTORE3 = "server3.keystore.jks";
//    private static final String MUTUALSSLSERVERTRUSTSTORE3 = "server3.truststore.jks";
//    private static final String SERVER1 = "mutualSSL1";
//    private static final String SERVER2 = "mutualSSL2";
//    private static final String SERVER3 = "mutualSSL3";
//    private static final String DEPLOYMENT_1 = "DEPLOYMENT_1";
//    private static final String DEPLOYMENT_2 = "DEPLOYMENT_2";
//    private static final String DEPLOYMENT_3 = "DEPLOYMENT_3";
//
//    @ArquillianResource
//    private Deployer deployer;
//
//    @ArquillianResource
//    private ContainerController containerController;
//
//    @Deployment(managed = false, name = DEPLOYMENT_1, order = 1)
//    @TargetsContainer(SERVER1)
//    public static Archive<?> deploy1() {
//        WebArchive archive = ShrinkWrap.create(WebArchive.class, "archive1" + ".war");
//        archive.addManifest();
//        return archive;
//    }
//
//    @Deployment(managed = false, name = DEPLOYMENT_2, order = 2)
//    @TargetsContainer(SERVER2)
//    public static Archive<?> deploy2() {
//        WebArchive archive = ShrinkWrap.create(WebArchive.class, "archive2" + ".war");
//        archive.addManifest();
//        return archive;
//    }
//
//    @Deployment(managed = false, name = DEPLOYMENT_3, order = 3)
//    @TargetsContainer(SERVER3)
//    public static Archive<?> deploy3() {
//        WebArchive archive = ShrinkWrap.create(WebArchive.class, "archive3" + ".war");
//        archive.addManifest();
//        return archive;
//    }
//
//    @Test
//    @RunAsClient
//    public void testClientDynamicSSLContext() {
//        AuthenticationContext context = doPrivileged((PrivilegedAction<AuthenticationContext>) () -> {
//            try {
//                URL config = getClass().getResource("test-wildfly-config.xml");
//                return ElytronXmlParser.parseAuthenticationClientConfiguration(config.toURI()).create();
//            } catch (Throwable t) {
//                throw new InvalidAuthenticationConfigurationException(t);
//            }
//        });
//
//        Runnable runnable =
//                () -> {
//                    try {
//                        DynamicSslContextSpi dynamicSslContextSpi = new DynamicSslContextSpi(SSLContext.getDefault());
//                        SSLContext delegatingSSLContext = new DynamicSSLContext(dynamicSslContextSpi, null, "https");
//                        delegatingSSLContext.getSocketFactory().getSupportedCipherSuites();
//
//                        // client instance with dynamic SSL Context configured
//                        Client client = ClientBuilder.newBuilder().sslContext(delegatingSSLContext).hostnameVerifier((s, sslSession) -> true).build();
//
//                        // run server with different SSLContexts configured and check if client uses correct SSLContext config based on target's port
//                        runServerWithMutualSSLThenTestClientAndReturnServerConfigToDefault(SERVER1, DEPLOYMENT_1, MUTUALSSLSERVERKEYSTORE, MUTUALSSLSERVERTRUSTSTORE, client, "archive1.war", 8443, 0);
//                        runServerWithMutualSSLThenTestClientAndReturnServerConfigToDefault(SERVER2, DEPLOYMENT_2, MUTUALSSLSERVERKEYSTORE2, MUTUALSSLSERVERTRUSTSTORE2, client, "archive2.war", 11443, 3000);
//                        runServerWithMutualSSLThenTestClientAndReturnServerConfigToDefault(SERVER3, DEPLOYMENT_3, MUTUALSSLSERVERKEYSTORE3, MUTUALSSLSERVERTRUSTSTORE3, client, "archive3.war", 14443, 6000);
//                    } catch (Exception e) {
//                        e.printStackTrace();
//                        Assert.fail();
//                    }
//                };
//        context.run(runnable);
//
//    }
//
//    private void runServerWithMutualSSLThenTestClientAndReturnServerConfigToDefault(String serverName, String deployment, String serverKeystore, String serverTruststore, Client client, String archiveName, int port, int portOffset) throws Exception {
//        if (!containerController.isStarted(serverName)) {
//            containerController.start(serverName);
//            secureServerWithMutualSSL(RESOURCES + serverKeystore,
//                    RESOURCES + serverTruststore, portOffset);
//            deployer.deploy(deployment);
//        }
//        Assert.assertEquals(client.target(String.format("https://localhost:%d/", port)).request().get().getStatus(), 200);
//        removeTLSConfigFromJbossHomeServer(portOffset, archiveName);
//        deployer.undeploy(deployment);
//        containerController.stop(serverName);
//    }
//
//    public static ModelNodeResult runCmd(OnlineManagementClient client, String cmd) throws Exception {
//        return client.execute(cmd);
//    }
//
//    public static OnlineManagementClient clientInit(int portOffset) throws IOException {
//        OnlineOptions onlineOptions = OnlineOptions
//                .standalone()
//                .hostAndPort("localhost", 9990 + portOffset)
//                .connectionTimeout(120000)
//                .build();
//        return ManagementClient.online(onlineOptions);
//    }
//
//    private static void secureServerWithMutualSSL(String serverKeystorePath, String serverTruststorePath, int portOffset) throws Exception {
//        File keystore = new File(serverKeystorePath);
//        File truststore = new File(serverTruststorePath);
//        serverKeystorePath = keystore.getAbsolutePath();
//        serverTruststorePath = truststore.getAbsolutePath();
//        OnlineManagementClient client = clientInit(portOffset);
//        runCmd(client, String.format("/subsystem=elytron/key-store=twoWayKS:add(path=%s,credential-reference={clear-text=%s},type=JKS)", serverKeystorePath, PASSWORD));
//        runCmd(client, String.format("/subsystem=elytron/key-store=twoWayTS:add(path=%s,credential-reference={clear-text=%s},type=JKS)", serverTruststorePath, PASSWORD));
//        runCmd(client, "/subsystem=elytron/key-manager=twoWayKM:add(key-store=twoWayKS,credential-reference={clear-text=secret})");
//        runCmd(client, "/subsystem=elytron/trust-manager=twoWayTM:add(key-store=twoWayTS)");
//        runCmd(client, "/subsystem=elytron/server-dynamic-context=twoWaySSC:add(key-manager=twoWayKM,protocols=[\"TLSv1.2\"],trust-manager=twoWayTM,need-client-auth=true)");
//        client.executeCli("batch");
//        client.executeCli("/subsystem=undertow/server=default-server/https-listener=https:undefine-attribute(name=security-realm)");
//        client.executeCli("/subsystem=undertow/server=default-server/https-listener=https:write-attribute(name=dynamic-context,value=twoWaySSC)\nrun-batch");
//        client.executeCli("run-batch");
//        Administration admin = new Administration(client, 240);
//        admin.reload();
//        client.close();
//    }
//
//    private static void removeTLSConfigFromJbossHomeServer(int portOffset, String archiveName) throws Exception {
//        OnlineManagementClient client = clientInit(portOffset);
//        client.executeCli("undeploy " + archiveName);
//        client.executeCli("batch");
//        client.executeCli("/subsystem=undertow/server=default-server/https-listener=https:write-attribute(name=security-realm,value=\"ApplicationRealm\")");
//        client.executeCli("/subsystem=undertow/server=default-server/https-listener=https:undefine-attribute(name=dynamic-context)\nrun-batch");
//        client.executeCli("run-batch");
//        runCmd(client, "/subsystem=elytron/server-dynamic-context=twoWaySSC:remove()");
//        runCmd(client, "/subsystem=elytron/trust-manager=twoWayTM:remove()");
//        runCmd(client, "/subsystem=elytron/key-manager=twoWayKM:remove()");
//        runCmd(client, "/subsystem=elytron/key-store=twoWayTS:remove()");
//        runCmd(client, "/subsystem=elytron/key-store=twoWayKS:remove()");
//        Administration admin = new Administration(client, 240);
//        admin.reload();
//        client.close();
//    }
}
