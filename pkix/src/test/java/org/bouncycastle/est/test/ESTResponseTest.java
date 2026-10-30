package org.bouncycastle.est.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLSession;

import junit.framework.TestCase;
import org.bouncycastle.est.ESTResponse;
import org.bouncycastle.est.LimitedSource;
import org.bouncycastle.est.Source;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;

public class ESTResponseTest
    extends TestCase
{

    private static Source<SSLSession> getMockSource(final InputStream data)
    {
        return new Source<SSLSession>()
        {
            @Override
            public InputStream getInputStream()
                throws IOException
            {
                return data;
            }

            @Override
            public OutputStream getOutputStream()
                throws IOException
            {
                return null;
            }

            @Override
            public SSLSession getSession()
            {
                return null;
            }

            @Override
            public void close()
                throws IOException
            {

            }
        };
    }

    private static InputStream buildHttp11Response(String statusLine, Map<String, String> httpHeader, boolean chunked, String messageBody)
    {
        final ByteArrayOutputStream responseData = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(responseData);

        // Protocol header
        pw.print(String.format("HTTP/1.1 %s\r\n", statusLine));

        // Header
        for (String header : httpHeader.keySet())
        {
            pw.print(String.format("%s: %s\r\n", header, httpHeader.get(header)));
        }

        pw.print("\r\n");

        // Message Body; supports chunked and non chunked representation
        if (messageBody != null && messageBody.length() != 0)
        {
            if (chunked)
            {
                // hex format string
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

    public void assertESTResponseMessageEquals(String expected, ESTResponse response)
    {
        try
        {
            byte[] data = Streams.readAll(response.getInputStream());
            String dataString = Strings.fromUTF8ByteArray(data);
            assertEquals(expected, dataString);
        }
        catch (IOException e)
        {
            fail("Error reading input stream data: " + e.getMessage());
        }
    }

    /**
     * Every header line was added to the header table by copying that header's value array, so a
     * response repeating one header many times was quadratic to parse: about 7 seconds per
     * megabyte of header lines, before any read limit applied. The values are collected once now.
     * <p>
     * The check is on how the parse time grows rather than on a wall-clock bound, so it holds on
     * a slow or loaded machine: eight times the header lines should cost about eight times as
     * much, where the quadratic version cost about sixty-four times as much.
     */
    public void testManyHeaderLinesStayLinear()
        throws IOException
    {
        int small = 50000;
        int large = 8 * small;

        ESTResponse response = new ESTResponse(null, getMockSource(new ByteArrayInputStream(headerLines(large))));
        assertEquals(large, ((String[])((Map)response.getHeaders()).get("x")).length);
        assertEquals("0", response.getHeader("Content-Length"));

        long smallTime = minParseNanos(headerLines(small), 3);
        long largeTime = minParseNanos(headerLines(large), 3);

        assertTrue("parse time grew by " + (largeTime / Math.max(smallTime, 1L)) + "x for 8x the header lines ("
            + smallTime / 1000000 + "ms, " + largeTime / 1000000 + "ms)", largeTime < 24 * smallTime);
    }

    private long minParseNanos(byte[] data, int runs)
        throws IOException
    {
        long best = Long.MAX_VALUE;
        for (int i = 0; i != runs; i++)
        {
            long start = System.nanoTime();
            new ESTResponse(null, getMockSource(new ByteArrayInputStream(data)));
            best = Math.min(best, System.nanoTime() - start);
        }
        return best;
    }

    private static byte[] headerLines(int lines)
    {
        StringBuilder sb = new StringBuilder("HTTP/1.1 200 OK\r\n");
        for (int i = 0; i < lines; i++)
        {
            sb.append("x: a\r\n");
        }
        sb.append("Content-Length: 0\r\n\r\n");

        return Strings.toByteArray(sb.toString());
    }

    /** The absolute read limit of a LimitedSource covers the header block, not only the body. */
    public void testHeaderBlockCountsAgainstReadLimit()
        throws IOException
    {
        StringBuilder sb = new StringBuilder("HTTP/1.1 200 OK\r\n");
        for (int i = 0; i < 2000; i++)
        {
            sb.append("x: a\r\n");
        }
        sb.append("Content-Length: 0\r\n\r\n");
        final byte[] data = Strings.toByteArray(sb.toString());

        // within the limit
        new ESTResponse(null, new LimitedMockSource(data, data.length + 1));

        try
        {
            new ESTResponse(null, new LimitedMockSource(data, 4096));
            fail("header block over the read limit was accepted");
        }
        catch (IOException e)
        {
            assertEquals("Absolute Read Limit exceeded by headers: 4096", e.getMessage());
        }
    }

    private static class LimitedMockSource
        implements Source<SSLSession>, LimitedSource
    {
        private final byte[] data;
        private final long limit;

        LimitedMockSource(byte[] data, long limit)
        {
            this.data = data;
            this.limit = limit;
        }

        public InputStream getInputStream()
        {
            return new ByteArrayInputStream(data);
        }

        public OutputStream getOutputStream()
        {
            return null;
        }

        public SSLSession getSession()
        {
            return null;
        }

        public void close()
        {
        }

        public Long getAbsoluteReadLimit()
        {
            return Long.valueOf(limit);
        }
    }

    public void testESTResponseShouldParseHttp11()
        throws IOException
    {
        String data = "Test message body";
        Map<String, String> httpHeader = new HashMap<String, String>();
        httpHeader.put("Content-Length", String.valueOf(data.length()));
        httpHeader.put("X-BC-EST-Header", "Test");

        InputStream testHttp11ResponseData = buildHttp11Response("200 OK", httpHeader, false, data);

        ESTResponse response = new ESTResponse(null, getMockSource(testHttp11ResponseData));

        assertEquals(200, response.getStatusCode());
        assertEquals(Long.valueOf(data.length()), response.getContentLength());
        assertEquals("Test", response.getHeader("X-BC-EST-Header"));
        assertEquals("OK", response.getStatusMessage());
        assertEquals("HTTP/1.1", response.getHttpVersion());
        assertESTResponseMessageEquals(data, response);
    }

    public void testESTResponseShouldSupportHttp11ChunkedTransferEncoding()
        throws IOException
    {
        String data = "Test message body";

        Map<String, String> httpHeader = new HashMap<String, String>();
        httpHeader.put("transfer-encoding", "chunked");

        InputStream testHttp11ResponseData = buildHttp11Response("200 OK", httpHeader, true, data);

        ESTResponse response = new ESTResponse(null, getMockSource(testHttp11ResponseData));
        assertESTResponseMessageEquals(data, response);
    }

    public void testESTResponseShouldSupportContentTransferEncodingBase64()
        throws IOException
    {
        String data = "Test message body";
        String dataBase64 = Base64.toBase64String(Strings.toUTF8ByteArray(data));

        Map<String, String> httpHeader = new HashMap<String, String>();
        httpHeader.put("content-transfer-encoding", "base64");
        httpHeader.put("content-length", String.valueOf(dataBase64.length()));

        InputStream testHttp11ResponseData = buildHttp11Response("200 OK", httpHeader, false, dataBase64);
        ESTResponse response = new ESTResponse(null, getMockSource(testHttp11ResponseData));

        assertESTResponseMessageEquals(data, response);
    }

    public void testESTResponseThrowsOnEmptyContentLengthAndNonChunkedTransferEncoding()
    {
        try
        {
            InputStream testHttp11ResponseData = buildHttp11Response("200 OK", new HashMap<String, String>(), false, "");
            new ESTResponse(null, getMockSource(testHttp11ResponseData));
            fail("ESTResponse should throw on empty content-length and non chunked transfer");
        }
        catch (IOException e)
        {
        }
    }

    public void testESTResponseThrowsOnNonEmptyContentLengthAndStatus204()
    {
        Map<String, String> httpHeader = new HashMap<String, String>();
        httpHeader.put("Content-Length", String.valueOf(5));
        InputStream testHttp11ResponseData = buildHttp11Response("204 OK", httpHeader, false, "");

        try
        {
            new ESTResponse(null, getMockSource(testHttp11ResponseData));
            fail("ESTResponse should throw on non empty content-length and HTTP Status 204");
        }
        catch (IOException e)
        {
        }
    }

    public void testESTResponseThrowsOnNegativeContentLength()
    {
        Map<String, String> httpHeader = new HashMap<String, String>();
        httpHeader.put("Content-Length", String.valueOf(-1));
        InputStream testHttp11ResponseData = buildHttp11Response("200 OK", httpHeader, false, "");

        try
        {
            new ESTResponse(null, getMockSource(testHttp11ResponseData));
            fail("ESTResponse should throw on negative content-length");
        }
        catch (IOException e)
        {
        }
    }

    // Regression test for issue #781: ESTService.getCSRAttributes received a
    // 404 response with a body and silently turned it into an obscure wrapper
    // exception ("Stream closed before limit fully read") instead of the actual
    // 404 status. Root cause: the body was never drained before resp.close(),
    // so the LimitedInputStream's "Content-Length not fully consumed" guard
    // tripped. Draining before close is sufficient and the fix in ESTService.
    public void testESTResponseCloseAfterDrain404WithBody()
        throws IOException
    {
        String body = "{\"error\":\"resource not found\"}";  // typical 55-byte JSON body
        Map<String, String> headers = new HashMap<String, String>();
        headers.put("Content-Length", String.valueOf(body.length()));

        // Pre-fix symptom: close without reading throws because the
        // LimitedInputStream has read 0 of N declared bytes.
        InputStream rawData = buildHttp11Response("404 Not Found", headers, false, body);
        ESTResponse undrained = new ESTResponse(null, getMockSource(rawData));
        assertEquals(404, undrained.getStatusCode());
        assertEquals(Long.valueOf(body.length()), undrained.getContentLength());
        try
        {
            undrained.close();
            fail("close() must complain when the body wasn't drained — that's the original bug");
        }
        catch (IOException expected)
        {
            assertTrue("expected limit-not-fully-read error, got: " + expected.getMessage(),
                expected.getMessage().contains("Stream closed before limit fully read"));
        }

        // Post-fix path: drain before close (what ESTService.getCSRAttributes
        // now does in its 204/404 branches) — close completes cleanly.
        InputStream rawData2 = buildHttp11Response("404 Not Found", headers, false, body);
        ESTResponse drained = new ESTResponse(null, getMockSource(rawData2));
        Streams.drain(drained.getInputStream());
        drained.close();   // must not throw
    }

    // Regression test for issue #1324: NullPointerException on HTTP/1.1 Transfer-Encoding chunked with Content-Transfer-Encoding base64
    public void testESTResponseMustNotThrowOnChunkedTransferEncodingWithContentTransferEncodingBase64()
        throws IOException
    {
        String data = "Test message body";
        String dataBase64 = Base64.toBase64String(Strings.toUTF8ByteArray(data));

        Map<String, String> httpHeader = new HashMap<String, String>();
        httpHeader.put("content-transfer-encoding", "base64");
        httpHeader.put("transfer-encoding", "chunked");

        InputStream testHttp11ResponseData = buildHttp11Response("200 OK", httpHeader, true, dataBase64);

        try
        {
            ESTResponse response = new ESTResponse(null, getMockSource(testHttp11ResponseData));
            assertESTResponseMessageEquals(data, response);
        }
        catch (IOException e)
        {
            fail("ESTResponse should not throw on a base64 encoded chunked transfer: " + e.getMessage());
        }
    }
}
