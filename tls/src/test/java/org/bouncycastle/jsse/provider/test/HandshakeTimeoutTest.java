package org.bouncycastle.jsse.provider.test;

import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import junit.framework.TestCase;

import org.bouncycastle.tls.TlsTimeoutException;

/**
 * Regression tests for github #1666: the BCJSSE blocking-socket handshake should honour the
 * total-handshake timeout configured via {@code org.bouncycastle.jsse.handshakeTimeoutMillis},
 * matching the semantics DTLS already provides through {@code TlsPeer.getHandshakeTimeoutMillis}.
 */
public class HandshakeTimeoutTest
    extends TestCase
{
    private static final String HANDSHAKE_TIMEOUT_PROPERTY = "org.bouncycastle.jsse.handshakeTimeoutMillis";
    private static final int HANDSHAKE_TIMEOUT_MS = 1000;

    private static final TrustManager[] TRUST_ALL = new TrustManager[]{ new X509TrustManager()
    {
        public void checkClientTrusted(X509Certificate[] chain, String authType)
        {
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
        {
        }

        public X509Certificate[] getAcceptedIssuers()
        {
            return new X509Certificate[0];
        }
    }};

    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    protected void tearDown()
    {
        System.clearProperty(HANDSHAKE_TIMEOUT_PROPERTY);
    }

    /**
     * A peer that accepts the connection but never sends a ServerHello. A per-read SO_TIMEOUT
     * would also catch this; here it confirms the timeout is wired up at all.
     */
    public void testStalledPeerTimesOut()
        throws Exception
    {
        System.setProperty(HANDSHAKE_TIMEOUT_PROPERTY, Integer.toString(HANDSHAKE_TIMEOUT_MS));

        final ServerSocket ss = new ServerSocket(0);
        ss.setSoTimeout(30000);

        startDaemon(new Runnable()
        {
            public void run()
            {
                try
                {
                    Socket s = ss.accept();
                    // Hold the connection open without ever responding to the ClientHello.
                    Thread.sleep(3L * HANDSHAKE_TIMEOUT_MS);
                    s.close();
                }
                catch (Exception ignored)
                {
                }
            }
        });

        assertTimesOut(ss);
    }

    /**
     * A peer that drips one byte at a time, each interval shorter than the handshake timeout but
     * for longer than it overall. No single read exceeds a per-read SO_TIMEOUT, so only a total
     * (wall-clock) handshake deadline can abort this - the case the fix actually closes.
     */
    public void testSlowDripPeerTimesOut()
        throws Exception
    {
        System.setProperty(HANDSHAKE_TIMEOUT_PROPERTY, Integer.toString(HANDSHAKE_TIMEOUT_MS));

        final ServerSocket ss = new ServerSocket(0);
        ss.setSoTimeout(30000);

        startDaemon(new Runnable()
        {
            public void run()
            {
                try
                {
                    Socket s = ss.accept();
                    OutputStream out = s.getOutputStream();
                    for (int i = 0; i < 100; ++i)
                    {
                        out.write(0x16);
                        out.flush();
                        Thread.sleep(HANDSHAKE_TIMEOUT_MS / 4);
                    }
                    s.close();
                }
                catch (Exception ignored)
                {
                }
            }
        });

        assertTimesOut(ss);
    }

    private void assertTimesOut(ServerSocket ss)
        throws Exception
    {
        SSLSocket cSock = createClientSocket(ss.getLocalPort());
        try
        {
            long start = System.currentTimeMillis();
            try
            {
                cSock.startHandshake();
                fail("handshake should have timed out");
            }
            catch (Exception e)
            {
                long elapsed = System.currentTimeMillis() - start;
                assertTrue("expected a TlsTimeoutException, got: " + e, isTimeout(e));
                assertTrue("handshake timed out too late (" + elapsed + "ms)",
                    elapsed < 5L * HANDSHAKE_TIMEOUT_MS);
            }
        }
        finally
        {
            closeQuietly(cSock);
            ss.close();
        }
    }

    private SSLSocket createClientSocket(int port)
        throws Exception
    {
        // NOTE: the SSLContext must be created after the property is set, since ContextData reads
        // it at initialization.
        SSLContext clientContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        clientContext.init(null, TRUST_ALL,
            SecureRandom.getInstance("DEFAULT", ProviderUtils.PROVIDER_NAME_BC));

        SSLSocketFactory fact = clientContext.getSocketFactory();
        return (SSLSocket)fact.createSocket("localhost", port);
    }

    private static void startDaemon(Runnable r)
    {
        Thread t = new Thread(r);
        t.setDaemon(true);
        t.start();
    }

    private static boolean isTimeout(Throwable e)
    {
        while (e != null)
        {
            if (e instanceof TlsTimeoutException)
            {
                return true;
            }
            e = e.getCause();
        }
        return false;
    }

    private static void closeQuietly(Socket s)
    {
        try
        {
            if (s != null)
            {
                s.close();
            }
        }
        catch (Exception ignored)
        {
        }
    }
}
