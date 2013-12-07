package org.bouncycastle.crypto.tls.test;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsServerProtocol;

public class TlsProtocolTest
    extends TestCase
{
    public void testClientServer()
        throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        PipedInputStream clientRead = new PipedInputStream();
        PipedInputStream serverRead = new PipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite, secureRandom);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite, secureRandom);

        ServerThread serverThread = new ServerThread(serverProtocol);
        serverThread.start();

        MockTlsClient client = new MockTlsClient(null);
        clientProtocol.connect(client);

        // byte[] data = new byte[64];
        // secureRandom.nextBytes(data);
        //
        // OutputStream output = clientProtocol.getOutputStream();
        // output.write(data);
        // output.close();
        //
        // byte[] echo = Streams.readAll(clientProtocol.getInputStream());
        serverThread.join();

        // assertTrue(Arrays.areEqual(data, echo));
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;

        ServerThread(TlsServerProtocol serverProtocol)
        {
            this.serverProtocol = serverProtocol;
        }

        public void run()
        {
            try
            {
                MockTlsServer server = new MockTlsServer();
                serverProtocol.accept(server);
                // Streams.pipeAll(serverProtocol.getInputStream(),
                // serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
                throw new RuntimeException(e);
            }
        }
    }
}
