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
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.MaxFragmentLength;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClient;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
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

        long time1 = System.currentTimeMillis();

        MockTlsClient client = new MockTlsClient(null);
        TlsClientProtocol protocol = openTlsConnection(address, port, client);
        protocol.close();

        long time2 = System.currentTimeMillis();
        System.out.println("Elapsed 1: " + (time2 - time1) + "ms");

        client = new MockTlsClient(client.getSessionToResume());
        protocol = openTlsConnection(address, port, client);

        long time3 = System.currentTimeMillis();
        System.out.println("Elapsed 2: " + (time3 - time2) + "ms");

        OutputStream output = protocol.getOutputStream();
        output.write("GET / HTTP/1.1\r\n\r\n".getBytes("UTF-8"));
        output.flush();

        InputStream input = protocol.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;
        while ((line = reader.readLine()) != null)
        {
            System.out.println(">>> " + line);
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
}
