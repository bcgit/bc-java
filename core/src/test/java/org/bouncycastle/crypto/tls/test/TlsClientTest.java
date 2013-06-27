package org.bouncycastle.crypto.tls.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ServerOnlyTlsAuthentication;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClient;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsSession;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS server.
 * <p/>
 * Please refer to GnuTLSSetup.txt or OpenSSLSetup.txt, and x509-*.pem files in this package for
 * help configuring an external TLS server.
 */
public class TlsClientTest
{
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args)
        throws Exception
    {
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;

//        long time1 = System.currentTimeMillis();

        MyTlsClient client = new MyTlsClient(null);
        TlsClientProtocol protocol = openTlsConnection(address, port, client);
        protocol.close();

//        long time2 = System.currentTimeMillis();
//        System.out.println("Elapsed 1: " + (time2 - time1) + "ms");

        client = new MyTlsClient(client.getSessionToResume());
        protocol = openTlsConnection(address, port, client);

//        long time3 = System.currentTimeMillis();
//        System.out.println("Elapsed 2: " + (time3 - time2) + "ms");

        OutputStream output = protocol.getOutputStream();
        output.write("GET / HTTP/1.1\r\n\r\n".getBytes("UTF-8"));
        output.flush();

        InputStream input = protocol.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;
        while ((line = reader.readLine()) != null)
        {
            System.out.println(line);
        }

        protocol.close();
    }

    static TlsClientProtocol openTlsConnection(InetAddress address, int port, TlsClient client) throws IOException
    {
        Socket s = new Socket(address, port);
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream(), secureRandom);
        protocol.connect(client);
        return protocol;
    }

    static class MyTlsClient
        extends DefaultTlsClient
    {
        TlsSession session;

        MyTlsClient(TlsSession session)
        {
            this.session = session;
        }

        public TlsSession getSessionToResume()
        {
            return this.session;
        }

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

        public int[] getCipherSuites()
        {
            return new int[]{CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA,};
        }

        public TlsAuthentication getAuthentication()
            throws IOException
        {
            return new ServerOnlyTlsAuthentication()
            {
                public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate)
                    throws IOException
                {
                    Certificate[] chain = serverCertificate.getCertificateList();
                    System.out.println("Received server certificate chain with " + chain.length + " entries");
                    for (int i = 0; i != chain.length; i++)
                    {
                        Certificate entry = chain[i];
                        System.out.println("    " + entry.getSubject());
                    }
                }
            };
        }

        public void notifyHandshakeComplete() throws IOException
        {
            super.notifyHandshakeComplete();

            TlsSession newSession = context.getResumableSession();
            if (newSession != null)
            {
                byte[] newSessionID = newSession.getSessionID();
                String hex = Hex.toHexString(newSessionID);

                if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
                {
                    System.out.println("Resumed session: " + hex);
                }
                else
                {
                    System.out.println("Established session: " + hex);
                }

                this.session = newSession;
            }
        }
    }
}
