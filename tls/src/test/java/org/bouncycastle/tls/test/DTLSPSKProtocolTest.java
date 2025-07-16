package org.bouncycastle.tls.test;

import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
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

        boolean correctException = false;

        try
        {
            DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);
            dtlsClient.close();
        }
        catch (TlsTimeoutException e)
        {
            correctException = true;
        }
        catch (Exception e)
        {
        }
        finally
        {
            clientTransport.close();
        }

        serverThread.shutdown();

        assertTrue(correctException);
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
