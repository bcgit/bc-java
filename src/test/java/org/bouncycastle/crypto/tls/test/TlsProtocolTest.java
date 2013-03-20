package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.tls.AbstractTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class TlsProtocolTest extends TestCase {

    public void testClientServer() throws Exception {

        SecureRandom secureRandom = new SecureRandom();

        PipedInputStream clientRead = new PipedInputStream();
        PipedInputStream serverRead = new PipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite, secureRandom);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite, secureRandom);

        ServerThread serverThread = new ServerThread(serverProtocol);
        serverThread.start();

        MyTlsClient client = new MyTlsClient();
        clientProtocol.connect(client);
        
        byte[] data = new byte[64];
        secureRandom.nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);
        output.close();

        byte[] echo = Streams.readAll(clientProtocol.getInputStream());
        serverThread.join();

        assertTrue(Arrays.areEqual(data, echo));
    }

    static class ServerThread extends Thread {
        private final TlsServerProtocol serverProtocol;

        ServerThread(TlsServerProtocol serverProtocol) {
            this.serverProtocol = serverProtocol;
        }

        public void run() {
            try {
                MyTlsServer server = new MyTlsServer();
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    static class MyTlsClient extends DefaultTlsClient {
        public TlsAuthentication getAuthentication() throws IOException {
            return new ServerOnlyTlsAuthentication() {
                public void notifyServerCertificate(
                    org.bouncycastle.crypto.tls.Certificate serverCertificate) throws IOException {
                }
            };
        }
    }

    static class MyTlsServer extends AbstractTlsServer {

        public TlsCredentials getCredentials() {
            // TODO
            return null;
        }

        public TlsKeyExchange getKeyExchange() throws IOException {
            // TODO
            return null;
        }
    }
}
