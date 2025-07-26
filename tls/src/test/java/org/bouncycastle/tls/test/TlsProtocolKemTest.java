package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

public abstract class TlsProtocolKemTest
    extends TestCase
{
    protected final TlsCrypto crypto;

    protected TlsProtocolKemTest(TlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    // mismatched ML-KEM groups w/o classical crypto
    public void testMismatchedGroups() throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        MockTlsKemClient client = new MockTlsKemClient(crypto, null);
        MockTlsKemServer server = new MockTlsKemServer(crypto);

        client.setNamedGroups(new int[]{ NamedGroup.MLKEM512 });
        server.setNamedGroups(new int[]{ NamedGroup.MLKEM768 });

        ServerThread serverThread = new ServerThread(serverProtocol, server, true);
        try
        {
            serverThread.start();
        }
        catch (Exception ignored)
        {
        }

        try
        {
            clientProtocol.connect(client);
            fail();
        }
        catch (Exception ignored)
        {
        }

        serverThread.join();
    }

    public void testMLKEM512() throws Exception
    {
        implTestClientServer(NamedGroup.MLKEM512);
    }

    public void testMLKEM768() throws Exception
    {
        implTestClientServer(NamedGroup.MLKEM768);
    }

    public void testMLKEM1024() throws Exception
    {
        implTestClientServer(NamedGroup.MLKEM1024);
    }

    private void implTestClientServer(int kemGroup) throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        MockTlsKemClient client = new MockTlsKemClient(crypto, null);
        MockTlsKemServer server = new MockTlsKemServer(crypto);

        client.setNamedGroups(new int[]{ kemGroup });
        server.setNamedGroups(new int[]{ kemGroup });

        ServerThread serverThread = new ServerThread(serverProtocol, server, false);
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
        private final boolean shouldFail;

        ServerThread(TlsServerProtocol serverProtocol, TlsServer server, boolean shouldFail)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.shouldFail = shouldFail;
        }

        public void run()
        {
            try
            {
                try
                {
                    serverProtocol.accept(server);
                    if (shouldFail)
                    {
                        fail();
                    }

                    Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                }
                catch (IOException ignored)
                {
                    if (!shouldFail)
                    {
                        fail();
                    }
                }

                serverProtocol.close();
            }
            catch (Exception e)
            {
            }
        }
    }
}
