package org.bouncycastle.est.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLSession;

import junit.framework.TestCase;
import org.bouncycastle.est.CSRRequestResponse;
import org.bouncycastle.est.ESTClient;
import org.bouncycastle.est.ESTClientProvider;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTRequest;
import org.bouncycastle.est.ESTResponse;
import org.bouncycastle.est.ESTService;
import org.bouncycastle.est.ESTServiceBuilder;
import org.bouncycastle.est.Source;

/**
 * Coverage for how {@link ESTService#getCSRAttributes()} disposes of a 204/404 error body.
 * <p>
 * RFC 7030 sec. 4.5 says such a body SHOULD be empty, but servers attach one anyway. The body must
 * be dealt with before close(), because the counter stream in ESTResponse refuses to close quietly
 * if a declared Content-Length was not consumed, or if bytes are still sitting in the pipe - and
 * that complaint used to be reported in place of the actual 404 (github #781).
 * <p>
 * Two properties are asserted, and they pull in opposite directions, which is why draining alone
 * cannot satisfy both:
 * <ul>
 * <li>the status survives - a failure while tidying up the connection is not reported instead of
 * the 404;</li>
 * <li>the drain never blocks - it must not read towards EOF, because a kept-alive HTTP/1.1
 * connection with no SO_TIMEOUT never delivers one.</li>
 * </ul>
 */
public class ESTServiceDrainTest
    extends TestCase
{
    private static final int TIMEOUT_SECONDS = 15;

    /**
     * close() objects because bytes are still in the pipe - the response declares a Content-Length
     * but the peer sent more after it. The drain consumes exactly the declared length, so those
     * extra bytes remain and trip the "extra content" check. The 404 must still be what the caller
     * sees; before the fix the close() IOException was promoted and masked it.
     */
    public void test404WithExtraBytesInPipeReportsStatusNotCloseFailure()
        throws Exception
    {
        String body = "{\"error\":\"resource not found\"}";
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Length", String.valueOf(body.length()));

        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        wire.write(readAll(buildHttp11Response("404 Not Found", headers, false, body)));
        wire.write("trailing junk from the peer".getBytes("US-ASCII"));

        CSRRequestResponse response = getCSRAttributes(new ByteArrayInputStream(wire.toByteArray()));

        assertFalse("a 404 must not be reported as holding CSR attributes", response.hasAttributesResponse());
    }

    /**
     * The anti-hang property. A chunked 404 whose terminating chunk never arrives: the stream serves
     * what it has, then reports nothing available and blocks on read() - exactly a kept-alive
     * connection with more promised and none coming. A drain that seeks EOF never returns. Run on a
     * daemon thread so a regression fails the test rather than wedging the build.
     */
    public void testTruncatedChunked404DoesNotBlock()
        throws Exception
    {
        // headers + one chunk, deliberately WITHOUT the terminating "0\r\n\r\n"
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(wire);
        pw.print("HTTP/1.1 404 Not Found\r\n");
        pw.print("transfer-encoding: chunked\r\n");
        pw.print("\r\n");
        String body = "{\"error\":\"no csrattrs\"}";
        pw.print(String.format("%X\r\n", body.length()));
        pw.print(body + "\r\n");
        pw.flush();

        final InputStream neverEnding = new BlockWhenExhaustedInputStream(wire.toByteArray());

        ExecutorService exec = Executors.newSingleThreadExecutor(new ThreadFactory()
        {
            public Thread newThread(Runnable r)
            {
                Thread t = new Thread(r, "ESTServiceDrainTest-drain");
                t.setDaemon(true);
                return t;
            }
        });
        try
        {
            Future fut = exec.submit(new Callable()
            {
                public Object call()
                    throws Exception
                {
                    return getCSRAttributes(neverEnding);
                }
            });

            try
            {
                CSRRequestResponse response = (CSRRequestResponse)fut.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
                assertFalse(response.hasAttributesResponse());
            }
            catch (TimeoutException e)
            {
                fut.cancel(true);
                fail("getCSRAttributes did not return within " + TIMEOUT_SECONDS
                    + "s: the error-body drain is reading towards an EOF that never comes");
            }
            catch (ExecutionException e)
            {
                // An ESTException here is acceptable - the point is that the call *returned*.
                // Anything else is a real failure.
                Throwable cause = e.getCause();
                if (!(cause instanceof ESTException))
                {
                    if (cause instanceof Exception)
                    {
                        throw (Exception)cause;
                    }
                    throw e;
                }
            }
        }
        finally
        {
            exec.shutdownNow();
        }
    }

    public void test404WithDeclaredLengthBodyIsDrainedCleanly()
        throws Exception
    {
        String body = "{\"error\":\"resource not found\"}";
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Length", String.valueOf(body.length()));

        CSRRequestResponse response = getCSRAttributes(
            buildHttp11Response("404 Not Found", headers, false, body));

        assertFalse(response.hasAttributesResponse());
    }

    public void test204ReportsNoAttributes()
        throws Exception
    {
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Length", "0");

        CSRRequestResponse response = getCSRAttributes(
            buildHttp11Response("204 No Content", headers, false, ""));

        assertFalse(response.hasAttributesResponse());
    }

    /**
     * Guards against the fix over-reaching. A 200 is not settled by its status - the body has to
     * parse - so an unparseable one must still raise, and a close() failure on that path must still
     * be reported rather than silently dropped.
     */
    public void test200WithGarbageBodyStillFails()
        throws Exception
    {
        String body = "not an ASN.1 sequence";
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Length", String.valueOf(body.length()));

        try
        {
            getCSRAttributes(buildHttp11Response("200 OK", headers, false, body));
            fail("a 200 carrying an unparseable body must raise ESTException");
        }
        catch (ESTException e)
        {
            // expected
        }
    }

    private static CSRRequestResponse getCSRAttributes(final InputStream wire)
        throws Exception
    {
        final Source<SSLSession> source = mockSource(wire);

        ESTService service = new ESTServiceBuilder("localhost:8443")
            .withClientProvider(new ESTClientProvider()
            {
                public ESTClient makeClient()
                {
                    return new ESTClient()
                    {
                        public ESTResponse doRequest(ESTRequest c)
                            throws IOException
                        {
                            return new ESTResponse(c, source);
                        }
                    };
                }

                public boolean isTrusted()
                {
                    return true;
                }
            }).build();

        return service.getCSRAttributes();
    }

    private static Source<SSLSession> mockSource(final InputStream data)
    {
        return new Source<SSLSession>()
        {
            public InputStream getInputStream()
            {
                return data;
            }

            public OutputStream getOutputStream()
            {
                return new ByteArrayOutputStream();
            }

            public SSLSession getSession()
            {
                return null;
            }

            public void close()
            {
            }
        };
    }

    /**
     * Serves the supplied bytes, then behaves like a socket on a kept-alive connection with more
     * data promised but none arriving: available() reports 0 and read() blocks rather than
     * returning -1.
     */
    private static class BlockWhenExhaustedInputStream
        extends InputStream
    {
        private final byte[] data;
        private int pos;

        BlockWhenExhaustedInputStream(byte[] data)
        {
            this.data = data;
        }

        public int available()
        {
            return data.length - pos;
        }

        public int read()
            throws IOException
        {
            if (pos < data.length)
            {
                return data[pos++] & 0xff;
            }
            throw block();
        }

        public int read(byte[] b, int off, int len)
            throws IOException
        {
            if (pos >= data.length)
            {
                throw block();
            }
            int n = Math.min(len, data.length - pos);
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }

        private IOException block()
            throws IOException
        {
            try
            {
                // Outlives the test's own timeout, so a drain that waits here is observed as a hang.
                Thread.sleep(TIMEOUT_SECONDS * 4000L);
                throw new IOException("blocked read woke up unexpectedly");
            }
            catch (InterruptedException e)
            {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted while blocked");
            }
        }
    }

    private static byte[] readAll(InputStream in)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[] buf = new byte[512];
        int n;
        while ((n = in.read(buf)) >= 0)
        {
            bOut.write(buf, 0, n);
        }
        return bOut.toByteArray();
    }

    private static InputStream buildHttp11Response(String statusLine, Map<String, String> httpHeader,
        boolean chunked, String messageBody)
    {
        ByteArrayOutputStream responseData = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(responseData);

        pw.print(String.format("HTTP/1.1 %s\r\n", statusLine));
        for (String header : httpHeader.keySet())
        {
            pw.print(String.format("%s: %s\r\n", header, httpHeader.get(header)));
        }
        pw.print("\r\n");

        if (messageBody != null && messageBody.length() != 0)
        {
            if (chunked)
            {
                pw.print(String.format("%X\r\n", messageBody.length()));
            }
            pw.print(messageBody + (chunked ? "\r\n" : ""));
            if (chunked)
            {
                pw.print("0\r\n");
                pw.print("\r\n");
            }
        }

        pw.flush();
        return new ByteArrayInputStream(responseData.toByteArray());
    }
}
