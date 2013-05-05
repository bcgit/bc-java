package org.bouncycastle.crypto.tls.test;

import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.tls.DTLSClientProtocol;
import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DatagramTransport;

public class DTLSProtocolTest extends TestCase {

    public void testClientServer() throws Exception {

        SecureRandom secureRandom = new SecureRandom();

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol(secureRandom);
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        clientTransport = new UnreliableDatagramTransport(clientTransport, secureRandom, 0, 0);

        clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

        MockDTLSClient client = new MockDTLSClient();
        DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);

        // byte[] data = new byte[64];
        // secureRandom.nextBytes(data);
        //
        // OutputStream output = clientProtocol.getOutputStream();
        // output.write(data);
        // output.close();
        //
        // byte[] echo = Streams.readAll(clientProtocol.getInputStream());

        dtlsClient.close();

        serverThread.shutdown();

        // assertTrue(Arrays.areEqual(data, echo));
    }

    static class ServerThread extends Thread {
        private final DTLSServerProtocol serverProtocol;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;

        ServerThread(DTLSServerProtocol serverProtocol, DatagramTransport serverTransport) {
            this.serverProtocol = serverProtocol;
            this.serverTransport = serverTransport;
        }

        public void run() {
            try {
                MockDTLSServer server = new MockDTLSServer();
                DTLSTransport dtlsServer = serverProtocol.accept(server, serverTransport);
                byte[] buf = new byte[dtlsServer.getReceiveLimit()];
                while (!isShutdown) {
                    int length = dtlsServer.receive(buf, 0, buf.length, 1000);
                    if (length >= 0) {
                        serverTransport.send(buf, 0, length);
                    }
                }
                dtlsServer.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        void shutdown() throws InterruptedException {
            if (!isShutdown) {
                isShutdown = true;
                this.join();
            }
        }
    }
}
