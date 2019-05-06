package org.bouncycastle.tls.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

import org.bouncycastle.tls.BasicTlsPSKIdentity;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.util.Strings;

/**
 * A simple test designed to conduct a TLS handshake with an external TLS server.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external TLS server.
 * </p><p>
 * In both cases, extra options are required to enable PSK ciphersuites and configure identities/keys.
 * </p>
 */
public class PSKTlsClientTest
{
    public static void main(String[] args) throws Exception
    {
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;

        long time1 = System.currentTimeMillis();

        /*
         * Note: This is the default PSK identity for 'openssl s_server' testing, the server must be
         * started with "-psk 6161616161" to make the keys match, and possibly the "-psk_hint"
         * option should be present.
         */
//        String psk_identity = "Client_identity";
//        byte[] psk = new byte[]{ 0x61, 0x61, 0x61, 0x61, 0x61 };

        // These correspond to the configuration of MockPSKTlsServer
        String psk_identity = "client";
        byte[] psk = Strings.toUTF8ByteArray("TLS_TEST_PSK");

        BasicTlsPSKIdentity pskIdentity = new BasicTlsPSKIdentity(psk_identity, psk);

        MockPSKTlsClient client = new MockPSKTlsClient(null, pskIdentity);
        TlsClientProtocol protocol = openTlsConnection(address, port, client);
        protocol.close();

        long time2 = System.currentTimeMillis();
        System.out.println("Elapsed 1: " + (time2 - time1) + "ms");

        client = new MockPSKTlsClient(client.getSessionToResume(), pskIdentity);
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
        TlsClientProtocol protocol = new TlsClientProtocol(s.getInputStream(), s.getOutputStream());
        protocol.connect(client);
        return protocol;
    }
}
