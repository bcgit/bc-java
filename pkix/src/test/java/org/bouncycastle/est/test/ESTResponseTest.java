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
