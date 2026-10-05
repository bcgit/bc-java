package org.bouncycastle.tls.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.ContentType;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DTLSVerifier;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.HandshakeType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import junit.framework.TestCase;

public class DTLSProtocolTest
    extends TestCase
{
    /**
     * A full handshake, with client authentication, at 10% packet loss in each direction.
     */
    public void testClientServer() throws Exception
    {
        MockDTLSClient client = new MockDTLSClient(null);
        MockDTLSServer server = new MockDTLSServer();

        implTestClientServer(client, server, 10);
    }

    /**
     * A full handshake, with client authentication, under heavy loss: most flights need several attempts.
     */
    public void testClientServerHighLoss() throws Exception
    {
        MockDTLSClient client = new MockDTLSClient(null);
        MockDTLSServer server = new MockDTLSServer();

        implTestClientServer(client, server, 25);
    }

    /**
     * @param handshakePacketLossPercent percentage of datagrams the client's transport loses, in each direction,
     *                                   while the handshake is in progress. The transport becomes reliable once
     *                                   the client's handshake completes, since application data is never
     *                                   retransmitted and the echo phase requires every datagram to arrive. A
     *                                   lossy handshake resends quickly, so that the flights that need several
     *                                   attempts keep the run short.
     */
    private void implTestClientServer(MockDTLSClient client, MockDTLSServer server, int handshakePacketLossPercent)
        throws Exception
    {
        if (handshakePacketLossPercent > 0)
        {
            client.setHandshakeResendTimeMillis(100);
            server.setHandshakeResendTimeMillis(100);
        }

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        UnreliableDatagramTransport lossyTransport = new UnreliableDatagramTransport(clientTransport, new Random(),
            handshakePacketLossPercent, handshakePacketLossPercent, TlsTestConfig.DTLS_MAX_DROPPED_DATAGRAMS,
            TlsTestConfig.DTLS_MAX_DROPPED_DATAGRAMS);
        clientTransport = lossyTransport;

        clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

        HandshakeGuardDatagramTransport guard = new HandshakeGuardDatagramTransport(clientTransport, lossyTransport,
            serverThread);
        clientTransport = guard;

        DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);
        guard.notifyHandshakeComplete();

        for (int i = 1; i <= 10; ++i)
        {
            byte[] data = new byte[i];
            Arrays.fill(data, (byte)i);
            dtlsClient.send(data, 0, data.length);
        }

        byte[] buf = new byte[dtlsClient.getReceiveLimit()];
        while (dtlsClient.receive(buf, 0, buf.length, 100) >= 0)
        {
        }

        dtlsClient.close();

        serverThread.shutdown();
    }

    /**
     * A client offering DTLS 1.3 must still negotiate DTLS 1.2 with a 1.2-only server, and its
     * ClientHello must be RFC 9147 5.3 shaped: legacy_version 0xfefd, an empty legacy_cookie, and
     * the offered versions in "supported_versions" with 0xfefc first.
     */
    public void testClientOffersDTLSv13NegotiatesDTLSv12() throws Exception
    {
        final ProtocolVersion[] clientVersions = ProtocolVersion.DTLSv13.downTo(ProtocolVersion.DTLSv10);
        final ProtocolVersion[] clientNegotiated = new ProtocolVersion[1];
        final ProtocolVersion[] serverNegotiated = new ProtocolVersion[1];

        MockDTLSClient client = new MockDTLSClient(null)
        {
            protected ProtocolVersion[] getSupportedVersions()
            {
                return clientVersions;
            }

            public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
            {
                super.notifyServerVersion(serverVersion);

                clientNegotiated[0] = serverVersion;
            }
        };

        MockDTLSServer server = new MockDTLSServer()
        {
            public ProtocolVersion getServerVersion() throws IOException
            {
                ProtocolVersion serverVersion = super.getServerVersion();

                serverNegotiated[0] = serverVersion;

                return serverVersion;
            }
        };

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        clientTransport = new UnreliableDatagramTransport(clientTransport, new Random(), 0, 0);

        CapturingDatagramTransport capture = new CapturingDatagramTransport(clientTransport);

        DTLSTransport dtlsClient = clientProtocol.connect(client, capture);

        dtlsClient.close();

        serverThread.shutdown();

        assertEquals("client negotiated version", ProtocolVersion.DTLSv12, clientNegotiated[0]);
        assertEquals("server negotiated version", ProtocolVersion.DTLSv12, serverNegotiated[0]);

        ClientHello clientHello = parseFirstClientHello(capture.getSent());
        assertNotNull("no ClientHello captured", clientHello);

        assertEquals("legacy_version", ProtocolVersion.DTLSv12, clientHello.getVersion());

        byte[] legacyCookie = clientHello.getCookie();
        assertNotNull("legacy_cookie", legacyCookie);
        assertEquals("legacy_cookie length", 0, legacyCookie.length);

        Hashtable clientExtensions = clientHello.getExtensions();
        assertNotNull("no extensions in ClientHello", clientExtensions);

        ProtocolVersion[] supportedVersions = TlsExtensionsUtils.getSupportedVersionsExtensionClient(
            clientExtensions);
        assertNotNull("missing supported_versions extension", supportedVersions);
        assertTrue("supported_versions empty", supportedVersions.length > 0);
        assertEquals("supported_versions[0]", ProtocolVersion.DTLSv13, supportedVersions[0]);
        assertTrue("supported_versions missing DTLSv12",
            ProtocolVersion.contains(supportedVersions, ProtocolVersion.DTLSv12));

        Vector clientShares = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        assertNotNull("missing key_share extension", clientShares);
        assertFalse("key_share offered no shares", clientShares.isEmpty());
    }

    private static ClientHello parseFirstClientHello(Vector datagrams) throws IOException
    {
        for (int i = 0; i < datagrams.size(); ++i)
        {
            byte[] datagram = (byte[])datagrams.elementAt(i);

            // DTLS 1.2 plaintext record header, then the DTLS handshake message header
            if (datagram.length < 25 || (datagram[0] & 0xFF) != ContentType.handshake
                || (datagram[13] & 0xFF) != HandshakeType.client_hello)
            {
                continue;
            }

            int fragmentLength = ((datagram[22] & 0xFF) << 16) | ((datagram[23] & 0xFF) << 8)
                | (datagram[24] & 0xFF);

            ByteArrayInputStream body = new ByteArrayInputStream(datagram, 25, fragmentLength);

            return ClientHello.parse(body, new ByteArrayOutputStream());
        }

        return null;
    }

    static class CapturingDatagramTransport
        implements DatagramTransport
    {
        private final DatagramTransport transport;
        private final Vector sent = new Vector();

        CapturingDatagramTransport(DatagramTransport transport)
        {
            this.transport = transport;
        }

        Vector getSent()
        {
            synchronized (sent)
            {
                return new Vector(sent);
            }
        }

        public int getReceiveLimit() throws IOException
        {
            return transport.getReceiveLimit();
        }

        public int getSendLimit() throws IOException
        {
            return transport.getSendLimit();
        }

        public int receive(byte[] buf, int off, int len, int waitMillis) throws IOException
        {
            return transport.receive(buf, off, len, waitMillis);
        }

        public void send(byte[] buf, int off, int len) throws IOException
        {
            byte[] datagram = new byte[len];
            System.arraycopy(buf, off, datagram, 0, len);
            synchronized (sent)
            {
                sent.addElement(datagram);
            }

            transport.send(buf, off, len);
        }

        public void close() throws IOException
        {
            transport.close();
        }
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final TlsServer server;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
        }

        public void run()
        {
            try
            {
                TlsCrypto serverCrypto = server.getCrypto();

                DTLSRequest request = null;

                // Use DTLSVerifier to require a HelloVerifyRequest cookie exchange before accepting
                {
                    DTLSVerifier verifier = new DTLSVerifier(serverCrypto);

                    // NOTE: Test value only - would typically be the client IP address
                    byte[] clientID = Strings.toUTF8ByteArray("MockDtlsClient");

                    int receiveLimit = serverTransport.getReceiveLimit();
                    int dummyOffset = serverCrypto.getSecureRandom().nextInt(16) + 1;
                    byte[] buf = new byte[dummyOffset + serverTransport.getReceiveLimit()];

                    do
                    {
                        if (isShutdown)
                            return;

                        int length = serverTransport.receive(buf, dummyOffset, receiveLimit, 100);
                        if (length > 0)
                        {
                            request = verifier.verifyRequest(clientID, buf, dummyOffset, length, serverTransport);
                        }
                    }
                    while (request == null);
                }

                // NOTE: A real server would handle each DTLSRequest in a new task/thread and continue accepting
                {
                    DTLSTransport dtlsTransport = serverProtocol.accept(server, serverTransport, request);
                    byte[] buf = new byte[dtlsTransport.getReceiveLimit()];
                    while (!isShutdown)
                    {
                        int length = dtlsTransport.receive(buf, 0, buf.length, 100);
                        if (length >= 0)
                        {
                            dtlsTransport.send(buf, 0, length);
                        }
                    }
                    dtlsTransport.close();
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }

        void shutdown()
            throws InterruptedException
        {
            if (!isShutdown)
            {
                isShutdown = true;
                this.join();
            }
        }
    }
}
