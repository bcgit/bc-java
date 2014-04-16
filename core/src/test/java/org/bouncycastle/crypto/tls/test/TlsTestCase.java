package org.bouncycastle.crypto.tls.test;

import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.SecureRandom;

import junit.framework.TestCase;

import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class TlsTestCase extends TestCase
{
    private static void checkTLSVersion(ProtocolVersion version)
    {
        if (version != null && !version.isTLS())
        {
            throw new IllegalStateException("Non-TLS version");
        }
    }

    protected final TlsTestConfig config;

    public TlsTestCase(TlsTestConfig config, String name)
    {
        checkTLSVersion(config.clientMinimumVersion);
        checkTLSVersion(config.clientOfferVersion);
        checkTLSVersion(config.serverMaximumVersion);
        checkTLSVersion(config.serverMinimumVersion);

        this.config = config;

        setName(name);
    }

    protected void runTest() throws Throwable
    {
        SecureRandom secureRandom = new SecureRandom();
        
        PipedInputStream clientRead = new PipedInputStream();
        PipedInputStream serverRead = new PipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        NetworkInputStream clientNetIn = new NetworkInputStream(clientRead);
        NetworkInputStream serverNetIn = new NetworkInputStream(serverRead);
        NetworkOutputStream clientNetOut = new NetworkOutputStream(clientWrite);
        NetworkOutputStream serverNetOut = new NetworkOutputStream(serverWrite);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientNetIn, clientNetOut, secureRandom);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverNetIn, serverNetOut, secureRandom);

        TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
        TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

        ServerThread serverThread = new ServerThread(serverProtocol, serverImpl);
        serverThread.start();

        Exception caught = null;
        try
        {
            clientProtocol.connect(clientImpl);

            // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
            int length = 1000;

            byte[] data = new byte[length];
            secureRandom.nextBytes(data);
    
            OutputStream output = clientProtocol.getOutputStream();
            output.write(data);
    
            byte[] echo = new byte[data.length];
            int count = Streams.readFully(clientProtocol.getInputStream(), echo);
    
            assertEquals(count, data.length);
            assertTrue(Arrays.areEqual(data, echo));
    
            output.close();
        }
        catch (Exception e)
        {
            caught = e;
            logException(caught);
        }

        serverThread.allowExit();
        serverThread.join();

        assertTrue("Client InputStream not closed", clientNetIn.isClosed());
        assertTrue("Client OutputStream not closed", clientNetOut.isClosed());
        assertTrue("Server InputStream not closed", serverNetIn.isClosed());
        assertTrue("Server OutputStream not closed", serverNetOut.isClosed());

        assertEquals("Client fatal alert connection end", config.expectFatalAlertConnectionEnd, clientImpl.firstFatalAlertConnectionEnd);
        assertEquals("Server fatal alert connection end", config.expectFatalAlertConnectionEnd, serverImpl.firstFatalAlertConnectionEnd);

        assertEquals("Client fatal alert description", config.expectFatalAlertDescription, clientImpl.firstFatalAlertDescription);
        assertEquals("Server fatal alert description", config.expectFatalAlertDescription, serverImpl.firstFatalAlertDescription);

        if (config.expectFatalAlertConnectionEnd == -1)
        {
            assertNull("Unexpected client exception", caught);
            assertNull("Unexpected server exception", serverThread.caught);
        }
    }

    protected  void logException(Exception e)
    {
        if (TlsTestConfig.DEBUG)
        {
            e.printStackTrace();
        }
    }

    class ServerThread extends Thread
    {
        protected final TlsServerProtocol serverProtocol;
        protected final TlsTestServerImpl serverImpl;

        boolean canExit = false;
        Exception caught = null;

        ServerThread(TlsServerProtocol serverProtocol, TlsTestServerImpl serverImpl)
        {
            this.serverProtocol = serverProtocol;
            this.serverImpl = serverImpl;
        }

        synchronized void allowExit()
        {
            canExit = true;
            this.notifyAll();
        }

        public void run()
        {
            try
            {
                serverProtocol.accept(serverImpl);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
                caught = e;
                logException(caught);
            }

            waitExit();
        }

        protected synchronized void waitExit()
        {
            while (!canExit)
            {
                try
                {
                    this.wait();
                }
                catch (InterruptedException e)
                {
                }
            }
        }
    }
}
