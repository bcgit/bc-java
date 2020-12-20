package org.bouncycastle.tls.test;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

public class TlsTestCase extends TestCase
{
    private static void checkTLSVersions(ProtocolVersion[] versions)
    {
        if (versions != null)
        {
            for (int i = 0; i < versions.length; ++i)
            {
                if (!versions[i].isTLS())
                {
                    throw new IllegalStateException("Non-TLS version");
                }
            }
        }
    }

    protected final TlsTestConfig config;

    public TlsTestCase(String name)
    {
        super(name);

        this.config = null;
    }

    public TlsTestCase(TlsTestConfig config, String name)
    {
        super(name);

        checkTLSVersions(config.clientSupportedVersions);
        checkTLSVersions(config.serverSupportedVersions);

        this.config = config;
    }

    public void testDummy()
    {
        // Avoid "No tests found" warning from junit
    }

    protected void runTest() throws Throwable
    {
        // Disable the test if it is not being run via TlsTestSuite
        if (config == null)
        {
            return;
        }

        SecureRandom secureRandom = new SecureRandom();
        
        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        NetworkInputStream clientNetIn = new NetworkInputStream(clientRead);
        NetworkInputStream serverNetIn = new NetworkInputStream(serverRead);
        NetworkOutputStream clientNetOut = new NetworkOutputStream(clientWrite);
        NetworkOutputStream serverNetOut = new NetworkOutputStream(serverWrite);

        InterruptedInputStream clientIn = new InterruptedInputStream(clientNetIn, secureRandom);
        InterruptedInputStream serverIn = new InterruptedInputStream(serverNetIn, secureRandom);

        clientIn.setPercentInterrupted(50);
        serverIn.setPercentInterrupted(50);

        TlsTestClientProtocol clientProtocol = new TlsTestClientProtocol(clientIn, clientNetOut, config);
        TlsTestServerProtocol serverProtocol = new TlsTestServerProtocol(serverIn, serverNetOut, config);

        clientProtocol.setResumableHandshake(true);
        serverProtocol.setResumableHandshake(true);

        TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
        TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

        ServerThread serverThread = new ServerThread(serverProtocol, serverImpl);
        serverThread.start();

        Exception caught = null;
        try
        {
            try
            {
                clientProtocol.connect(clientImpl);
            }
            catch (InterruptedIOException e)
            {
                completeHandshake(clientProtocol);
            }

            // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
            int length = 1000;

            byte[] data = new byte[length];
            secureRandom.nextBytes(data);
    
            OutputStream output = clientProtocol.getOutputStream();
            output.write(data);
    
            byte[] echo = new byte[data.length];
            int count = readFully(clientProtocol.getInputStream(), echo, 0, echo.length);
    
            assertEquals(count, data.length);
            assertTrue(Arrays.areEqual(data, echo));

            assertTrue(Arrays.areEqual(clientImpl.tlsServerEndPoint, serverImpl.tlsServerEndPoint));

            if (!TlsUtils.isTLSv13(clientImpl.negotiatedVersion))
            {
                assertNotNull(clientImpl.tlsUnique);
                assertNotNull(serverImpl.tlsUnique);
            }
            assertTrue(Arrays.areEqual(clientImpl.tlsUnique, serverImpl.tlsUnique));

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

    protected void logException(Exception e)
    {
        if (TlsTestConfig.DEBUG)
        {
            e.printStackTrace();
        }
    }

    static void completeHandshake(TlsProtocol protocol)
        throws IOException
    {
        while (protocol.isHandshaking())
        {
            try
            {
                protocol.resumeHandshake();
            }
            catch (InterruptedIOException e)
            {
            }
        }
    }

    static int interruptibleRead(InputStream inStr, byte[] buf, int off, int len)
        throws IOException
    {
        for (;;)
        {
            try
            {
                return inStr.read(buf, off, len);
            }
            catch (InterruptedIOException e)
            {
            }
        }
    }

    static void pipeAll(InputStream inStr, OutputStream outStr)
        throws IOException
    {
        byte[] bs = new byte[4096];
        int numRead;
        while ((numRead = interruptibleRead(inStr, bs, 0, bs.length)) >= 0)
        {
            outStr.write(bs, 0, numRead);
        }
    }

    static int readFully(InputStream inStr, byte[] buf, int off, int len)
        throws IOException
    {
        int totalRead = 0;
        while (totalRead < len)
        {
            int numRead = interruptibleRead(inStr, buf, off + totalRead, len - totalRead);
            if (numRead < 0)
            {
                break;
            }
            totalRead += numRead;
        }
        return totalRead;
    }

    class ServerThread extends Thread
    {
        protected final TlsTestServerProtocol serverProtocol;
        protected final TlsTestServerImpl serverImpl;

        boolean canExit = false;
        Exception caught = null;

        ServerThread(TlsTestServerProtocol serverProtocol, TlsTestServerImpl serverImpl)
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
                try
                {
                    serverProtocol.accept(serverImpl);
                }
                catch (InterruptedIOException e)
                {
                    completeHandshake(serverProtocol);
                }

                pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
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
