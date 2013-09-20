package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;

public class TlsProtocolTest
    extends TestCase
{
    public void testClientServer()
        throws Exception
    {
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

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;

        ServerThread(TlsServerProtocol serverProtocol)
        {
            this.serverProtocol = serverProtocol;
        }

        public void run()
        {
            try
            {
                MyTlsServer server = new MyTlsServer();
                serverProtocol.accept(server);
                // Streams.pipeAll(serverProtocol.getInputStream(),
                // serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        }
    }

    static class MyTlsClient
        extends DefaultTlsClient
    {
        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
                + ")");
            if (message != null)
            {
                out.println(message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS client received alert (AlertLevel." + alertLevel + ", AlertDescription."
                + alertDescription + ")");
        }

        public TlsAuthentication getAuthentication()
            throws IOException
        {
            return new TlsAuthentication()
            {
                public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate)
                    throws IOException
                {
                    Certificate[] chain = serverCertificate.getCertificateList();
                    System.out.println("Received server certificate chain of length " + chain.length);
                    for (int i = 0; i != chain.length; i++)
                    {
                        Certificate entry = chain[i];
                        // TODO Create fingerprint based on certificate signature algorithm digest
                        System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                            + entry.getSubject() + ")");
                    }
                }

                public TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
                    throws IOException
                {
                    short[] certificateTypes = certificateRequest.getCertificateTypes();
                    if (certificateTypes != null)
                    {
                        for (int i = 0; i < certificateTypes.length; ++i)
                        {
                            if (certificateTypes[i] == ClientCertificateType.rsa_sign)
                            {
                                // TODO Create a distinct client certificate for use here
                                return TlsTestUtils.loadSignerCredentials(context, new String[]{"x509-server.pem",
                                    "x509-ca.pem"}, "x509-server-key.pem");
                            }
                        }
                    }
                    return null;
                }
            };
        }
    }

    static class MyTlsServer
        extends DefaultTlsServer
    {
        public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Exception cause)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server raised alert (AlertLevel." + alertLevel + ", AlertDescription." + alertDescription
                + ")");
            if (message != null)
            {
                out.println(message);
            }
            if (cause != null)
            {
                cause.printStackTrace(out);
            }
        }

        public void notifyAlertReceived(short alertLevel, short alertDescription)
        {
            PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
            out.println("TLS server received alert (AlertLevel." + alertLevel + ", AlertDescription."
                + alertDescription + ")");
        }

        public CertificateRequest getCertificateRequest()
        {
            return new CertificateRequest(new short[]{ ClientCertificateType.rsa_sign }, null, null);
        }

        public void notifyClientCertificate(org.bouncycastle.crypto.tls.Certificate clientCertificate)
            throws IOException
        {
            Certificate[] chain = clientCertificate.getCertificateList();
            System.out.println("Received client certificate chain of length " + chain.length);
            for (int i = 0; i != chain.length; i++)
            {
                Certificate entry = chain[i];
                // TODO Create fingerprint based on certificate signature algorithm digest
                System.out.println("    fingerprint:SHA-256 " + TlsTestUtils.fingerprint(entry) + " ("
                    + entry.getSubject() + ")");
            }
        }

        protected TlsEncryptionCredentials getRSAEncryptionCredentials()
            throws IOException
        {
            return TlsTestUtils.loadEncryptionCredentials(context, new String[]{"x509-server.pem", "x509-ca.pem"},
                "x509-server-key.pem");
        }

        protected TlsSignerCredentials getRSASignerCredentials()
            throws IOException
        {
            return TlsTestUtils.loadSignerCredentials(context, new String[]{"x509-server.pem", "x509-ca.pem"},
                "x509-server-key.pem");
        }
    }
}
