package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Vector;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsFatalAlertReceived;
import org.bouncycastle.tls.TlsPSKExternal;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

public class Tls13PSKProtocolTest
    extends TestCase
{
    public void testBadClientKey() throws Exception
    {
        MockPSKTls13Client client = new MockPSKTls13Client(true);
        MockPSKTls13Server server = new MockPSKTls13Server();

        implTestKeyMismatch(client, server);
    }

    public void testBadServerKey() throws Exception
    {
        MockPSKTls13Client client = new MockPSKTls13Client();
        MockPSKTls13Server server = new MockPSKTls13Server(true);

        implTestKeyMismatch(client, server);
    }

    public void testClientServer() throws Exception
    {
        MockPSKTls13Client client = new MockPSKTls13Client();
        MockPSKTls13Server server = new MockPSKTls13Server();

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

    public void testServerExternalPSKAbortWithAlert() throws Exception
    {
        // github #1673: a server can now abort PSK selection with a chosen alert by throwing from
        // getExternalPSK (which is only possible because the method declares throws IOException).
        MockPSKTls13Client client = new MockPSKTls13Client();
        MockPSKTls13Server server = new MockPSKTls13Server()
        {
            public TlsPSKExternal getExternalPSK(Vector identities) throws IOException
            {
                throw new TlsFatalAlert(AlertDescription.unknown_psk_identity);
            }
        };

        implTestClientReceivesAlert(client, server, AlertDescription.unknown_psk_identity);
    }

    private void implTestKeyMismatch(MockPSKTls13Client client, MockPSKTls13Server server) throws Exception
    {
        implTestClientReceivesAlert(client, server, AlertDescription.decrypt_error);
    }

    private void implTestClientReceivesAlert(MockPSKTls13Client client, MockPSKTls13Server server, short expectedAlert)
        throws Exception
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
        assertEquals(expectedAlert, alertDescription);
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
