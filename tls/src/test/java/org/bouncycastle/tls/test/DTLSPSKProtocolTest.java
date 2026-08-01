package org.bouncycastle.tls.test;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsFatalAlertReceived;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsTimeoutException;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

public class DTLSPSKProtocolTest
    extends TestCase
{
    public void testBadClientKeyTimeout() throws Exception
    {
        MockPSKDTLSClient client = new MockPSKDTLSClient(null, true);
        MockPSKDTLSServer server = new MockPSKDTLSServer();

        implTestKeyMismatch(client, server);
    }

    public void testBadServerKeyTimeout() throws Exception
    {
        MockPSKDTLSClient client = new MockPSKDTLSClient(null);
        MockPSKDTLSServer server = new MockPSKDTLSServer(true);

        implTestKeyMismatch(client, server);
    }

    public void testClientServer() throws Exception
    {
        MockPSKDTLSClient client = new MockPSKDTLSClient(null);
        MockPSKDTLSServer server = new MockPSKDTLSServer();

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        clientTransport = new UnreliableDatagramTransport(clientTransport, client.getCrypto().getSecureRandom(), 0, 0);

        clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

        DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);

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

    private void implTestKeyMismatch(MockPSKDTLSClient client, MockPSKDTLSServer server) throws Exception
    {
        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        // Don't use unreliable transport because we are focused on timeout due to bad PSK
//        clientTransport = new UnreliableDatagramTransport(clientTransport, client.getCrypto().getSecureRandom(), 0, 0);

        clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

        Exception clientFailure = null;

        try
        {
            DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);
            dtlsClient.close();
        }
        catch (Exception e)
        {
            clientFailure = e;
        }
        finally
        {
            clientTransport.close();
        }

        serverThread.shutdown();

        Exception serverFailure = serverThread.getFailure();

        // The PSKs do not match, so the handshake cannot complete and both peers run out of patience.
        // Both use the same handshake timeout, so which of them notices first is a race: the client
        // either hits its own timeout, or - when the server gets there first - receives the
        // internal_error alert the server raises on ITS timeout. Both outcomes are the timeout this test
        // is about, so accept either, but require that a timeout is what actually happened on the side
        // that reported it rather than accepting internal_error on its own.
        assertNotNull("Handshake unexpectedly succeeded with mismatched PSKs", clientFailure);

        if (!(clientFailure instanceof TlsTimeoutException))
        {
            assertTrue("Expected a handshake timeout, client failed with: " + clientFailure,
                clientFailure instanceof TlsFatalAlertReceived
                    && ((TlsFatalAlertReceived)clientFailure).getAlertDescription() == AlertDescription.internal_error);
            assertTrue("Client received internal_error but the server did not time out; server failed with: "
                    + serverFailure,
                serverFailure instanceof TlsTimeoutException);
        }
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final TlsServer server;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;
        private volatile Exception failure = null;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
        }

        /**
         * Return the exception that terminated this thread, or null if it shut down cleanly. A
         * key-mismatch test needs this to tell the server timing out from the server failing some other
         * way, since either shows up at the client as an internal_error alert.
         */
        Exception getFailure()
        {
            return failure;
        }

        public void run()
        {
            try
            {
                DTLSTransport dtlsServer = serverProtocol.accept(server, serverTransport);
                byte[] buf = new byte[dtlsServer.getReceiveLimit()];
                while (!isShutdown)
                {
                    int length = dtlsServer.receive(buf, 0, buf.length, 100);
                    if (length >= 0)
                    {
                        dtlsServer.send(buf, 0, length);
                    }
                }
                dtlsServer.close();
            }
            catch (Exception e)
            {
                failure = e;
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
