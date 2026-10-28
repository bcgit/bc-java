package org.bouncycastle.tls.test;

import java.io.IOException;

import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

/**
 * DTLS 1.3 handshakes over the ML-KEM hybrid groups of RFC 10024 and the pure ML-KEM groups of
 * draft-ietf-tls-mlkem. The TLS 1.3 tests of the same groups (TlsProtocolHybridTest, TlsProtocolKemTest)
 * never reach the DTLS record layer, where a ClientHello carrying an ML-KEM key share no longer fits one
 * datagram and has to be fragmented (RFC 9147 5.5), so this exercises that path for each group. The MTU
 * is deliberately small enough that every group's key share is split.
 */
public class DTLS13ProtocolHybridTest
    extends TestCase
{
    private static final int MTU = 1200;

    private final TlsCrypto crypto = new BcTlsCrypto();

    public void testSecP256r1MLKEM768() throws Exception
    {
        implTestClientServer(NamedGroup.SecP256r1MLKEM768);
    }

    public void testSecP384r1MLKEM1024() throws Exception
    {
        implTestClientServer(NamedGroup.SecP384r1MLKEM1024);
    }

    public void testX25519MLKEM768() throws Exception
    {
        implTestClientServer(NamedGroup.X25519MLKEM768);
    }

    public void testMLKEM768() throws Exception
    {
        implTestClientServer(NamedGroup.MLKEM768);
    }

    private void implTestClientServer(int namedGroup) throws Exception
    {
        final int[] clientNegotiatedGroup = new int[]{ -1 };
        final int[] serverNegotiatedGroup = new int[]{ -1 };

        MockTlsHybridClient client = new MockTlsHybridClient(crypto, null)
        {
            protected ProtocolVersion[] getSupportedVersions()
            {
                return ProtocolVersion.DTLSv13.only();
            }

            public void notifyHandshakeComplete() throws IOException
            {
                super.notifyHandshakeComplete();

                clientNegotiatedGroup[0] = context.getSecurityParametersConnection().getNegotiatedGroup();
            }
        };
        MockTlsHybridServer server = new MockTlsHybridServer(crypto)
        {
            protected ProtocolVersion[] getSupportedVersions()
            {
                return ProtocolVersion.DTLSv13.only();
            }

            public void notifyHandshakeComplete() throws IOException
            {
                super.notifyHandshakeComplete();

                serverNegotiatedGroup[0] = context.getSecurityParametersConnection().getNegotiatedGroup();
            }
        };

        client.setNamedGroups(new int[]{ namedGroup });
        server.setNamedGroups(new int[]{ namedGroup });

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(MTU);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DTLSTransport dtlsClient = clientProtocol.connect(client, network.getClient());

        assertEquals("client negotiated group", namedGroup, clientNegotiatedGroup[0]);

        byte[] data = new byte[200];
        crypto.getSecureRandom().nextBytes(data);
        dtlsClient.send(data, 0, data.length);

        byte[] buf = new byte[dtlsClient.getReceiveLimit()];
        int length = dtlsClient.receive(buf, 0, buf.length, 5000);

        assertEquals("echoed application data length", data.length, length);
        assertTrue("echoed application data differs", Arrays.areEqual(data, Arrays.copyOf(buf, length)));

        dtlsClient.close();

        serverThread.shutdown();

        assertNull("server failed", serverThread.getCaught());
        assertEquals("server negotiated group", namedGroup, serverNegotiatedGroup[0]);
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final TlsServer server;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;
        private volatile Exception caught = null;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
        }

        Exception getCaught()
        {
            return caught;
        }

        public void run()
        {
            try
            {
                DTLSTransport dtlsTransport = serverProtocol.accept(server, serverTransport);

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
            catch (Exception e)
            {
                this.caught = e;
                e.printStackTrace();
            }
        }

        void shutdown() throws InterruptedException
        {
            if (!isShutdown)
            {
                isShutdown = true;
                this.join();
            }
        }
    }
}
