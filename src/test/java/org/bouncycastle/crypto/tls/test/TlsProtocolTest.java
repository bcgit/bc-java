package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
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

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite,
            secureRandom);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite,
            secureRandom);

        ServerThread serverThread = new ServerThread(serverProtocol);
        serverThread.start();

        MyTlsClient client = new MyTlsClient();
        clientProtocol.connect(client);

//        byte[] data = new byte[64];
//        secureRandom.nextBytes(data);
//
//        OutputStream output = clientProtocol.getOutputStream();
//        output.write(data);
//        output.close();
//
//        byte[] echo = Streams.readAll(clientProtocol.getInputStream());
        serverThread.join();

//        assertTrue(Arrays.areEqual(data, echo));
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
//                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
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

    static class MyTlsServer extends DefaultTlsServer {
        public TlsCredentials getCredentials() throws IOException {
            switch (selectedCipherSuite) {
            case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
            case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
                return TlsTestUtils.loadEncryptionCredentials(context, new String[] {
                    "x509-server.pem", "x509-ca.pem" }, "x509-server-key.pem");

            case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
            case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
                return TlsTestUtils.loadSignerCredentials(context, new String[] { "x509-server.pem",
                    "x509-ca.pem" }, "x509-server-key.pem");

            default:
                /*
                 * Note: internal error here; selected a key exchange we don't implement!
                 */
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }
    }
}
