package org.bouncycastle.tls.test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;

import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.UDPTransport;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS server.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external DTLS server.
 * </p>
 */
public class DTLSClientTest
{
    private static final SecureRandom secureRandom = new SecureRandom();

    public static void main(String[] args)
        throws Exception
    {
        InetAddress address = InetAddress.getLocalHost();
        int port = 5556;

        TlsSession session = createSession(address, port);

        MockDTLSClient client = new MockDTLSClient(session);

        DTLSTransport dtls = openDTLSConnection(address, port, client);

        System.out.println("Receive limit: " + dtls.getReceiveLimit());
        System.out.println("Send limit: " + dtls.getSendLimit());

        // Send and hopefully receive a packet back

        byte[] request = "Hello World!\n".getBytes("UTF-8");
        dtls.send(request, 0, request.length);

        byte[] response = new byte[dtls.getReceiveLimit()];
        int received = dtls.receive(response, 0, response.length, 30000);
        if (received >= 0)
        {
            System.out.println(new String(response, 0, received, "UTF-8"));
        }

        dtls.close();
    }

    private static TlsSession createSession(InetAddress address, int port)
        throws IOException
    {
        MockDTLSClient client = new MockDTLSClient(null);
        DTLSTransport dtls = openDTLSConnection(address, port, client);
        TlsSession session = client.getSessionToResume();
        dtls.close();
        return session;
    }

    private static DTLSTransport openDTLSConnection(InetAddress address, int port, TlsClient client)
        throws IOException
    {
        DatagramSocket socket = new DatagramSocket();
        socket.connect(address, port);

        int mtu = 1500;
        DatagramTransport transport = new UDPTransport(socket, mtu);
        transport = new UnreliableDatagramTransport(transport, secureRandom, 0, 0);
        transport = new LoggingDatagramTransport(transport, System.out);

        DTLSClientProtocol protocol = new DTLSClientProtocol();

        return protocol.connect(client, transport);
    }
}
