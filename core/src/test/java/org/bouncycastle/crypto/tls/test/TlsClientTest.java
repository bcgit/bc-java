package org.bouncycastle.crypto.tls.test;

import java.io.IOException;
import java.io.InputStream;
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
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.util.io.Streams;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS server.
 * <p/>
 * Please refer to GnuTLSSetup.txt or OpenSSLSetup.txt, and x509-*.pem files in this package for
 * help configuring an external TLS server.
 */
public class TlsClientTest
{

    public static void main(String[] args)
        throws Exception
    {

        Socket socket = new Socket(InetAddress.getLocalHost(), 5556);

        SecureRandom secureRandom = new SecureRandom();
        TlsClientProtocol protocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream(),
            secureRandom);

        MyTlsClient client = new MyTlsClient();
        protocol.connect(client);

        OutputStream output = protocol.getOutputStream();
        output.write("GET / HTTP/1.1\r\n\r\n".getBytes("UTF-8"));

        InputStream input = protocol.getInputStream();
        byte[] result = Streams.readAll(input);

        System.out.println(new String(result, "UTF-8"));

        protocol.close();
        socket.close();
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
    }
}
