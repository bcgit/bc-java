package org.bouncycastle.crypto.tls.test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.tls.DTLSServerProtocol;
import org.bouncycastle.crypto.tls.DTLSTransport;
import org.bouncycastle.crypto.tls.DatagramTransport;
import org.bouncycastle.crypto.tls.UDPTransport;

/**
 * A simple test designed to conduct a DTLS handshake with an external DTLS client.
 * <p>
 * Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in
 * this package (under 'src/test/resources') for help configuring an external DTLS client.
 * </p>
 */
public class DTLSServerTest
{
    public static void main(String[] args)
        throws Exception
    {
        int port = 5556;

        int mtu = 1500;

        SecureRandom secureRandom = new SecureRandom();

        DTLSServerProtocol serverProtocol = new DTLSServerProtocol(secureRandom);

        byte[] data = new byte[mtu];
        DatagramPacket packet = new DatagramPacket(data, mtu);

        DatagramSocket socket = new DatagramSocket(port);
        socket.receive(packet);

        System.out.println("Accepting connection from " + packet.getAddress().getHostAddress() + ":" + port);
        socket.connect(packet.getAddress(), packet.getPort());

        /*
         * NOTE: For simplicity, and since we don't yet have HelloVerifyRequest support, we just
         * discard the initial packet, which the client should re-send anyway.
         */

        DatagramTransport transport = new UDPTransport(socket, mtu);
        
        // Uncomment to see packets
//        transport = new LoggingDatagramTransport(transport, System.out);

        MockDTLSServer server = new MockDTLSServer();
        DTLSTransport dtlsServer = serverProtocol.accept(server, transport);

        byte[] buf = new byte[dtlsServer.getReceiveLimit()];

        while (!socket.isClosed())
        {
            try
            {
                int length = dtlsServer.receive(buf, 0, buf.length, 60000);
                if (length >= 0)
                {
                    System.out.write(buf, 0, length);
                    dtlsServer.send(buf, 0, length);
                }
            }
            catch (SocketTimeoutException ste)
            {
            }
        }

        dtlsServer.close();
    }
}
