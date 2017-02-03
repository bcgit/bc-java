package org.bouncycastle.est.http;

import org.bouncycastle.est.http.enc.CTEBase64InputStream;
import org.bouncycastle.util.Strings;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A basic http response.
 */
public class ESTHttpResponse
{
    private final ESTHttpRequest originalRequest;
    private final Map<String, List<String>> headers;
    private String HttpVersion;
    private int statusCode;
    private String statusMessage;
    private final byte[] lineBuffer;
    private final Socket socket;

    private InputStream inputStream;
    private long contentLength = -1;

    public ESTHttpResponse(ESTHttpRequest originalRequest, Socket socket)
        throws Exception
    {
        this.socket = socket;
        this.originalRequest = originalRequest;

        this.inputStream = new PrintingInputStream(socket.getInputStream());
        socket = null;

        this.headers = new HashMap<String, List<String>>();
        this.lineBuffer = new byte[1024];
        process();
    }


    public ESTHttpResponse(ESTHttpRequest originalRequest, InputStream inputStream)
        throws Exception
    {
        this.originalRequest = originalRequest;

        this.inputStream = inputStream;
        socket = null;

        this.headers = new HashMap<String, List<String>>();
        this.lineBuffer = new byte[1024];

        process();
    }

    private void process()
        throws Exception
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
        throws Exception
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

    public ESTHttpRequest getOriginalRequest()
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

    public Socket getSocket()
    {
        return socket;
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
        throws Exception
    {
        if (this.socket != null)
        {
            this.socket.close();
        }
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
