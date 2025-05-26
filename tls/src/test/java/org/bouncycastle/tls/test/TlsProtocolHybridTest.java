package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

public abstract class TlsProtocolHybridTest
    extends TestCase
{
    protected final TlsCrypto crypto;

    protected TlsProtocolHybridTest(TlsCrypto crypto)
    {
        this.crypto = crypto;
    }

    // mismatched hybrid groups w/o non-hybrids
    public void testMismatchedGroups() throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(crypto, serverProtocol, new int[]{ NamedGroup.X25519MLKEM768 }, true);
        try
        {
            serverThread.start();
        }
        catch (Exception ignored)
        {
        }

        MockTlsHybridClient client = new MockTlsHybridClient(crypto, null);
        client.setNamedGroups(new int[]{ NamedGroup.SecP256r1MLKEM768 });
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

    private void implTestClientServer(int hybridGroup) throws Exception
    {
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(crypto, serverProtocol, new int[]{ hybridGroup }, false);
        serverThread.start();

        MockTlsHybridClient client = new MockTlsHybridClient(crypto, null);
        client.setNamedGroups(new int[]{ hybridGroup });

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
        private final TlsCrypto crypto;
        private final TlsServerProtocol serverProtocol;
        private final int[] namedGroups;
        private boolean shouldFail = false;

        ServerThread(TlsCrypto crypto, TlsServerProtocol serverProtocol, int[] namedGroups, boolean shouldFail)
        {
            this.crypto = crypto;
            this.serverProtocol = serverProtocol;
            this.namedGroups = namedGroups;
            this.shouldFail = shouldFail;
        }

        public void run()
        {
            try
            {
                MockTlsHybridServer server = new MockTlsHybridServer(crypto);
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
