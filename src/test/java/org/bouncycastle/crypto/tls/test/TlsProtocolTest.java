package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;

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

        // byte[] data = new byte[64];
        // secureRandom.nextBytes(data);
        //
        // OutputStream output = clientProtocol.getOutputStream();
        // output.write(data);
        // output.close();
        //
        // byte[] echo = Streams.readAll(clientProtocol.getInputStream());
        serverThread.join();

        // assertTrue(Arrays.areEqual(data, echo));
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
                // Streams.pipeAll(serverProtocol.getInputStream(),
                // serverProtocol.getOutputStream());
                serverProtocol.close();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    static class MyTlsClient extends DefaultTlsClient {

        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause) {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
                + ")");
            if (message != null) {
                out.println(message);
            }
            if (cause != null) {
                cause.printStackTrace(out);
            }
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription) {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client received alert (AlertLevel." + alertLevel + ", AlertDescription."
                + alertDescription + ")");
        }

        public TlsAuthentication getAuthentication() throws IOException {
            return new ServerOnlyTlsAuthentication() {
                public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate)
                    throws IOException {
                }
            };
        }
    }

    static class MyTlsServer extends DefaultTlsServer {

        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause) {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
                + ")");
            if (message != null) {
                out.println(message);
            }
            if (cause != null) {
                cause.printStackTrace(out);
            }
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription) {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server received alert (AlertLevel." + alertLevel + ", AlertDescription."
                + alertDescription + ")");
        }

        protected TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {
            return TlsTestUtils.loadEncryptionCredentials(context, new String[] { "x509-server.pem", "x509-ca.pem" },
                "x509-server-key.pem");
        }

        protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
            return TlsTestUtils.loadSignerCredentials(context, new String[] { "x509-server.pem", "x509-ca.pem" },
                "x509-server-key.pem");
        }
    }
}
