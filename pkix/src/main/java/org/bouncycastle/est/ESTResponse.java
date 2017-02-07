package org.bouncycastle.est;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * A basic http response.
 */
public class ESTResponse
{
    private final ESTRequest originalRequest;
    private final Map<String, List<String>> headers;
    private final byte[] lineBuffer;
    private final Source source;
    private String HttpVersion;
    private int statusCode;
    private String statusMessage;
    private InputStream inputStream;
    private long contentLength = -1;


    public ESTResponse(ESTRequest originalRequest, Source source)
        throws IOException
    {
        this.originalRequest = originalRequest;
        this.source = source;

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

        this.headers = new HashMap<String, List<String>>();
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
                List<String> l = headers.get(k);
                if (l == null)
                {
                    l = new ArrayList<String>();
                    headers.put(k, l);
                }
                l.add(line.substring(i + 1).trim());
            }
            line = readStringIncluding('\n');
        }

        if ("base64".equalsIgnoreCase(getHeader("content-transfer-encoding")))
        {
            inputStream = new CTEBase64InputStream(inputStream, getContentLength());
        }


    }

    public String getHeader(String key)
    {
        List<String> l = headers.get(Strings.toLowerCase(key));
        if (l == null || l.isEmpty())
        {
            return "";
        }
        return l.get(0);
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

    public Map<String, List<String>> getHeaders()
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

    public long getContentLength()
    {
        List<String> v = headers.get("content-length");
        if (v == null || v.isEmpty())
        {
            return -1;
        }
        return Long.parseLong(v.get(0));
    }

    public void close()
        throws IOException
    {
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
            System.out.print(String.valueOf((char)i));
            return i;
        }
    }
}
