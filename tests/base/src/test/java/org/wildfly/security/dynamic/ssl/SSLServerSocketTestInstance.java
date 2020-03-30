package org.wildfly.security.dynamic.ssl;

import org.junit.Assert;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

public class SSLServerSocketTestInstance {

    private int port;
    private String keystorePath;
    private String truststorePath;
    private String password = "passphrase";

    SSLServerSocketTestInstance(String pathToKeystore, String pathToTruststore, int port) {
        this.keystorePath = pathToKeystore;
        this.truststorePath = pathToTruststore;
        this.port = port;
    }

    public void run() {
        SSLContext sslContext = DynamicSSLTestUtils.createSSLContext(this.keystorePath, this.truststorePath, this.password);
        try {
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            javax.net.ssl.SSLServerSocket sslServerSocket = (javax.net.ssl.SSLServerSocket) sslServerSocketFactory.createServerSocket(this.port);
            System.out.println("SSL server started");
            new Thread(() -> {

                while (true) {
                    SSLSocket sslSocket = null;
                    try {
                        sslSocket = (SSLSocket) sslServerSocket.accept();
                        new ServerThread(sslSocket).start();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }).start();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    // Thread handling the socket from client
    static class ServerThread extends Thread {
        private SSLSocket sslSocket;

        ServerThread(SSLSocket sslSocket) {
            this.sslSocket = sslSocket;
        }

        public void run() {
            try {
                sslSocket.startHandshake();
                // if successful return 200
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
                printWriter.print("HTTP/1.1 200\r\n");
                printWriter.flush();
                sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
                Assert.fail();
            }
        }
    }
}
