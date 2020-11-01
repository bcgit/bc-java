package org.bouncycastle.est;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * A basic http response.
 */
public class ESTResponse
{
    private final ESTRequest originalRequest;
    private final HttpUtil.Headers headers;
    private final byte[] lineBuffer;
    private final Source source;
    private String HttpVersion;
    private int statusCode;
    private String statusMessage;
    private InputStream inputStream;
    private Long contentLength;
    private long read = 0;
    private Long absoluteReadLimit;

    private static final Long ZERO = 0L;

    public ESTResponse(ESTRequest originalRequest, Source source)
        throws IOException
    {
        this.originalRequest = originalRequest;
        this.source = source;

        if (source instanceof LimitedSource)
        {
            this.absoluteReadLimit = ((LimitedSource)source).getAbsoluteReadLimit();
        }

        Set<String> opts = Properties.asKeySet("org.bouncycastle.debug.est");
        if (opts.contains("input") ||
            opts.contains("all"))
        {
            this.inputStream = new PrintingInputStream(source.getInputStream());
        }
        else
        {
            this.inputStream = source.getInputStream();
        }

        this.headers = new HttpUtil.Headers();
        this.lineBuffer = new byte[1024];

        process();
    }

    private void process()
        throws IOException
    {
        //
        // Status line.
        //
        HttpVersion = readStringIncluding(' ');
        this.statusCode = Integer.parseInt(readStringIncluding(' '));
        this.statusMessage = readStringIncluding('\n');


        //
        // Headers.
        //
        String line = readStringIncluding('\n');
        int i;
        while (line.length() > 0)
        {
            i = line.indexOf(':');
            if (i > -1)
            {
                String k = Strings.toLowerCase(line.substring(0, i).trim()); // Header keys are case insensitive
                headers.add(k, line.substring(i + 1).trim());
            }
            line = readStringIncluding('\n');
        }


        contentLength = getContentLength();

        //
        // Concerned that different servers may or may not set a Content-length
        // for these success types. In this case we will arbitrarily set content length
        // to zero.
        //
        if (statusCode == 204 || statusCode == 202)
        {
            if (contentLength == null)
            {
                contentLength = 0L;
            }
            else
            {
                if (statusCode == 204 && contentLength > 0)
                {
                    throw new IOException("Got HTTP status 204 but Content-length > 0.");
                }
            }
        }

        if (contentLength == null)
        {
            throw new IOException("No Content-length header.");
        }

        if (contentLength.equals(ZERO))
        {

            //
            // The server is likely to hang up the socket and any attempt to read can
            // result in a broken pipe rather than an eof.
            // So we will return a dummy input stream that will return eof to anything that reads from it.
            //

            inputStream = new InputStream()
            {
                public int read()
                    throws IOException
                {
                    return -1;
                }
            };
        }

        if (contentLength < 0)
        {
            throw new IOException("Server returned negative content length: " + absoluteReadLimit);
        }

        if (absoluteReadLimit != null && contentLength >= absoluteReadLimit)
        {
            throw new IOException("Content length longer than absolute read limit: " + absoluteReadLimit + " Content-Length: " + contentLength);
        }


        inputStream = wrapWithCounter(inputStream, absoluteReadLimit);
        //
        // Observed that some
        //
        if ("base64".equalsIgnoreCase(getHeader("content-transfer-encoding")))
        {
            inputStream = new CTEBase64InputStream(inputStream, getContentLength());
        }
    }

    public String getHeader(String key)
    {
        return headers.getFirstValue(key);
    }


    protected InputStream wrapWithCounter(final InputStream in, final Long absoluteReadLimit)
    {
        return new InputStream()
        {
            public int read()
                throws IOException
            {
                int i = in.read();
                if (i > -1)
                {
                    read++;
                    if (absoluteReadLimit != null && read >= absoluteReadLimit)
                    {
                        throw new IOException("Absolute Read Limit exceeded: " + absoluteReadLimit);
                    }
                }
                return i;
            }

            public void close()
                throws IOException
            {
                if (contentLength != null && contentLength - 1 > read)
                {
                    throw new IOException("Stream closed before limit fully read, Read: " + read + " ContentLength: " + contentLength);
                }

                if (in.available() > 0)
                {
                    throw new IOException("Stream closed with extra content in pipe that exceeds content length.");
                }

                in.close();
            }
        };
    }


    protected String readStringIncluding(char until)
        throws IOException
    {
        int c = 0;
        int j;
        do
        {
            j = inputStream.read();
            lineBuffer[c++] = (byte)j;
            if (c >= lineBuffer.length)
            {
                throw new IOException("Server sent line > " + lineBuffer.length);
            }
        }
        while (j != until && j > -1);
        if (j == -1)
        {
            throw new EOFException();
        }

        return new String(lineBuffer, 0, c).trim();
    }

    public ESTRequest getOriginalRequest()
    {
        return originalRequest;
    }

    public HttpUtil.Headers getHeaders()
    {
        return headers;
    }

    public String getHttpVersion()
    {
        return HttpVersion;
    }

    public int getStatusCode()
    {
        return statusCode;
    }

    public String getStatusMessage()
    {
        return statusMessage;
    }

    public InputStream getInputStream()
    {
        return inputStream;
    }


    public Source getSource()
    {
        return source;
    }

    public Long getContentLength()
    {
        String v = headers.getFirstValue("Content-Length");
        if (v == null)
        {
            return null;
        }
        try
        {
            return Long.parseLong(v);
        }
        catch (RuntimeException nfe)
        {
            throw new RuntimeException("Content Length: '" + v + "' invalid. " + nfe.getMessage());
        }
    }

    public void close()
        throws IOException
    {
        if (inputStream != null)
        {
            inputStream.close();
        }
        this.source.close();
    }


    private class PrintingInputStream
        extends InputStream
    {
        private final InputStream src;

        private PrintingInputStream(InputStream src)
        {
            this.src = src;
        }

        public int read()
            throws IOException
        {
            int i = src.read();
            return i;
        }

        public int available()
            throws IOException
        {
            return src.available();
        }

        public void close()
            throws IOException
        {
            src.close();
        }
    }
}
