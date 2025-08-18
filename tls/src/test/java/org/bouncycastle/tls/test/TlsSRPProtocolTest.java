package org.bouncycastle.tls.test;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

public class TlsSRPProtocolTest
    extends TestCase
{
    public void testClientServer() throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        MockSRPTlsClient client = new MockSRPTlsClient(null, MockSRPTlsServer.TEST_SRP_IDENTITY);
        MockSRPTlsServer server = new MockSRPTlsServer();

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
                //throw new RuntimeException(e);
            }
        }
    }
}
