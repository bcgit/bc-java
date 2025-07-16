package org.bouncycastle.tls.test;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlertReceived;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

public class TlsPSKProtocolTest
    extends TestCase
{
    public void testBadClientKey() throws Exception
    {
        MockPSKTlsClient client = new MockPSKTlsClient(null, true);
        MockPSKTlsServer server = new MockPSKTlsServer();

        implTestKeyMismatch(client, server);
    }

    public void testBadServerKey() throws Exception
    {
        MockPSKTlsClient client = new MockPSKTlsClient(null);
        MockPSKTlsServer server = new MockPSKTlsServer(true);

        implTestKeyMismatch(client, server);
    }

    public void testClientServer() throws Exception
    {
        MockPSKTlsClient client = new MockPSKTlsClient(null);
        MockPSKTlsServer server = new MockPSKTlsServer();

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol, server);
        serverThread.start();

        clientProtocol.connect(client);

        // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
        int length = 1000;

        byte[] data = new byte[length];
        client.getCrypto().getSecureRandom().nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(count, data.length);
        assertTrue(Arrays.areEqual(data, echo));

        output.close();

        serverThread.join();
    }

    private void implTestKeyMismatch(MockPSKTlsClient client, MockPSKTlsServer server) throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol, server);
        serverThread.start();

        boolean correctException = false;
        short alertDescription = -1;

        try
        {
            clientProtocol.connect(client);
        }
        catch (TlsFatalAlertReceived e)
        {
            correctException = true;
            alertDescription = e.getAlertDescription();
        }
        catch (Exception e)
        {
        }
        finally
        {
            clientProtocol.close();
        }

        serverThread.join();

        assertTrue(correctException);
        assertEquals(AlertDescription.bad_record_mac, alertDescription);        
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;
        private final TlsServer server;

        ServerThread(TlsServerProtocol serverProtocol, TlsServer server)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
        }

        public void run()
        {
            try
            {
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
            }
        }
    }
}
