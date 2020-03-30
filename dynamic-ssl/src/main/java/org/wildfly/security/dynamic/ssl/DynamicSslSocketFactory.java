package org.wildfly.security.dynamic.ssl;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DynamicSslSocketFactory extends SSLSocketFactory {

    private DynamicSSLContextSPI dynamicSSLContextImpl;
    private volatile String[] intersectionCipherSuite;
    private SSLSocketFactory configuredDefaultSslSocketFactory;

    public DynamicSslSocketFactory(SSLSocketFactory configuredDefaultSslSocketFactory, DynamicSSLContextSPI dynamicSSLContextImpl) {
        super();
        this.configuredDefaultSslSocketFactory = configuredDefaultSslSocketFactory;
        this.dynamicSSLContextImpl = dynamicSSLContextImpl;
    }

    @Override
    public Socket createSocket() throws IOException {
        return configuredDefaultSslSocketFactory.createSocket();
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        return createSocketBasedOnPeerInfo(null, port, address, null, null, null, null);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return createSocketBasedOnPeerInfo(host, port, null, null, null, null, null);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException {
        return createSocketBasedOnPeerInfo(host, port, null, localAddress, localPort, null, null);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return createSocketBasedOnPeerInfo(null, port, address, localAddress, localPort, null, null);

    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
        return createSocketBasedOnPeerInfo(host, port, null, null, null, socket, autoClose);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return dynamicSSLContextImpl.getConfiguredDefault().getSocketFactory().getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        String[] val = intersectionCipherSuite;
        if (val == null) {
            synchronized (this) {
                val = intersectionCipherSuite;
                if (intersectionCipherSuite == null) {
                    val = intersectionCipherSuite = getIntersection();
                }
            }
        }
        return val;
    }

    private Socket createSocketBasedOnPeerInfo(String hostname, Integer port, InetAddress address, InetAddress localAddress, Integer localPort, Socket socket, Boolean autoClose) throws IOException {
        try {
            SSLSocketFactory socketFactory = this.dynamicSSLContextImpl.getSSLContext(new URI(null, null, hostname == null ? address.getHostName() : hostname, port, null, null, null))
                    .getSocketFactory();

            // resolve socket
            if (socket != null && autoClose != null) {
                return socketFactory.createSocket(socket, hostname, port, autoClose);
            }

            // resolves InetAddresses callbacks
            if (address != null) {
                return localAddress == null ?
                        socketFactory.createSocket(address, port) : socketFactory.createSocket(address, port, localAddress, localPort);
            }
            if (localAddress != null && localPort != null) {
                return socketFactory.createSocket(hostname, port, localAddress, localPort);
            }

            // default
            return socketFactory.createSocket(hostname, port);
        } catch (URISyntaxException e) {
            throw new UnknownHostException(e.getMessage());
        }
    }

    private String[] getIntersection() {
        List<SSLContext> sslContexts = dynamicSSLContextImpl.getConfiguredSSLContexts();
        Map<String, Integer> counts = new HashMap<>();
        List<String> intersection = new ArrayList<>();
        sslContexts.forEach(c -> {
            String[] cipherSuites = c.getSocketFactory().getSupportedCipherSuites();
            for (String cipherSuite : cipherSuites) {
                counts.merge(cipherSuite, 1, (a, b) -> a + b);
            }
        });
        counts.forEach((c, v) -> {
            if (sslContexts.size() == v) {
                intersection.add(c);
            }
        });
        return intersection.toArray(new String[0]);
    }
}
