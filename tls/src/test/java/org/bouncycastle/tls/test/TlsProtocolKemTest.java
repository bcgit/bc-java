package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

public class TlsProtocolKemTest
    extends TestCase
{
    // mismatched ML-KEM strengths w/o classical crypto
    public void testMismatchStrength() throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol, new int[]{ NamedGroup.MLKEM768 }, true);
        try
        {
            serverThread.start();
        }
        catch (Exception ignored)
        {
        }
        MockTlsKemClient client = new MockTlsKemClient(null);
        client.setNamedGroups(new int[]{ NamedGroup.MLKEM512 });
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

    public void testClientServer() throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol, null, false);
        serverThread.start();

        MockTlsKemClient client = new MockTlsKemClient(null);
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
        private final int[] namedGroups;
        private boolean shouldFail = false;

        ServerThread(TlsServerProtocol serverProtocol, int[] namedGroups, boolean shouldFail)
        {
            this.serverProtocol = serverProtocol;
            this.namedGroups = namedGroups;
            this.shouldFail = shouldFail;
        }

        public void run()
        {
            try
            {
                MockTlsKemServer server = new MockTlsKemServer();
                if (namedGroups != null)
                {
                    server.setNamedGroups(namedGroups);
                }

                try
                {
                    serverProtocol.accept(server);
                    if (shouldFail)
                    {
                        fail();
                    }
                }
                catch (IOException ignored)
                {
                    if (!shouldFail)
                    {
                        fail();
                    }
                }

                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
//                throw new RuntimeException(e);
            }
        }
    }
}
