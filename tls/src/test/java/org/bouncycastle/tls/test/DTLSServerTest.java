package org.bouncycastle.tls.test;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.DTLSRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DTLSVerifier;
import org.bouncycastle.tls.DatagramSender;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.UDPTransport;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

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
        final int mtu = 1500;

        DTLSVerifier verifier = new DTLSVerifier(new BcTlsCrypto(new SecureRandom()));
        DTLSRequest request = null;

        byte[] data = new byte[mtu];
        final DatagramPacket packet = new DatagramPacket(data, mtu);
        final DatagramSocket socket = new DatagramSocket(port);

        /*
         * Process incoming packets, replying with HelloVerifyRequest, until one is verified.
         */
        do
        {
            socket.receive(packet);

            request = verifier.verifyRequest(packet.getAddress().getAddress(), data, 0, packet.getLength(), new DatagramSender()
            {
                public int getSendLimit() throws IOException
                {
                    return mtu - 28;
                }

                public void send(byte[] buf, int off, int len) throws IOException
                {
                    if (len > getSendLimit())
                    {
                        throw new TlsFatalAlert(AlertDescription.internal_error);
                    }

                    socket.send(new DatagramPacket(buf, off, len, packet.getAddress(), packet.getPort()));
                }
            });
        }
        while (null == request);

        /*
         * Proceed to a handshake, passing verified 'request' (ClientHello) to DTLSServerProtocol.accept.
         */
        System.out.println("Accepting connection from " + packet.getAddress().getHostAddress() + ":" + packet.getPort());
        socket.connect(packet.getAddress(), packet.getPort());

        DatagramTransport transport = new UDPTransport(socket, mtu);

        // Uncomment to see packets
//        transport = new LoggingDatagramTransport(transport, System.out);

        MockDTLSServer server = new MockDTLSServer();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        DTLSTransport dtlsServer = serverProtocol.accept(server, transport, request);

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
