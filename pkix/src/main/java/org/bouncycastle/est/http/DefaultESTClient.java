package org.bouncycastle.est.http;


import org.bouncycastle.est.ESTException;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class DefaultESTClient
    implements ESTHttpClient
{
    private final ESTClientSSLSocketProvider sslSocketProvider;
    private static final Charset utf8 = Charset.forName("UTF-8");
    private static byte[] CRLF = new byte[]{'\r', '\n'};

    public DefaultESTClient(ESTClientSSLSocketProvider sslSocketProvider)
    {
        this.sslSocketProvider = sslSocketProvider;
    }


    public ESTHttpResponse doRequest(ESTHttpRequest req)
        throws Exception
    {
        ESTHttpResponse resp = null;
        ESTHttpRequest r = req;
        int rcCount = 15;
        do
        {
            resp = performRequest(r);
            r = redirectURL(resp);
        }
        while (r != null && --rcCount > 0); // Follow redirects.

        if (rcCount == 0)
        {
            throw new ESTException("Too many redirects..");
        }

        return resp;
    }

    protected ESTHttpRequest redirectURL(ESTHttpResponse response)
        throws Exception
    {
        ESTHttpRequest redirectingRequest = null;

        if (response.getStatusCode() >= 300 && response.getStatusCode() <= 399)
        {

            switch (response.getStatusCode())
            {
            case 301:
            case 302:
            case 303:
            case 306:
            case 307:
                String loc = response.getHeader("Location");
                if ("".equals(loc))
                {
                    throw new ESTException("Redirect status type: " + response.getStatusCode() + " but no location header");
                }

                if (loc.startsWith("http"))
                {
                    redirectingRequest = response.getOriginalRequest().newWithURL(new URL(loc));
                }
                else
                {
                    URL u = response.getOriginalRequest().url;
                    redirectingRequest = response.getOriginalRequest().newWithURL(new URL(u.getProtocol(), u.getHost(), u.getPort(), loc));
                }
                break;
            default:
                throw new ESTException("Client does not handle http status code: " + response.getStatusCode());
            }
        }

        if (redirectingRequest != null)
        {
            response.close(); // Close original request.
        }

        return redirectingRequest;
    }


    public ESTHttpResponse performRequest(ESTHttpRequest c)
        throws Exception
    {
        c.setEstHttpClient(this);
        Socket sock = null;
        ESTHttpResponse res = null;
        Source socketSource = null;
        try
        {
            sock = new Socket(c.url.getHost(), c.url.getPort());
            socketSource = sslSocketProvider.wrapSocket(sock, c.url.getHost(), c.url.getPort());

          //  socketSource = new SSLSocketSource((SSLSocket)sock);

            OutputStream os = new PrintingOutputStream(socketSource.getOutputStream());
//            InputStream in = new PrintingInputStream(sock.getInputStream());

            String req = c.url.getPath() + ((c.url.getQuery() != null) ? c.url.getQuery() : "");

            // Replace host header.

            c.headers.put("Host", Collections.singletonList(c.url.getHost()));
            writeLine(os, c.method + " " + req + " HTTP/1.1");


            for (Map.Entry<String, List<String>> ent : c.headers.entrySet())
            {
                for (String v : ent.getValue())
                {
                    writeLine(os, ent.getKey() + ": " + v);
                }
            }

            os.write(CRLF);
            os.flush();
            if (c.writer != null)
            {
                c.writer.ready(os);
            }
            os.flush();

            if (c.hijacker != null)
            {
                res = c.hijacker.hijack(c, socketSource);
                return res;
            }
            else
            {
                res = new ESTHttpResponse(c, socketSource);
            }

            return res;

        }
        finally
        {
            // Close only if response not generated.
            if (sock != null && res == null)
            {
                sock.close();
            }
        }

    }


    private static void writeLine(OutputStream os, String s)
        throws Exception
    {
        os.write(s.getBytes());
        os.write(CRLF);
    }


    private class PrintingOutputStream
        extends OutputStream
    {
        private final OutputStream tgt;

        public PrintingOutputStream(OutputStream tgt)
        {
            this.tgt = tgt;
        }

        public void write(int b)
            throws IOException
        {
            System.out.print(String.valueOf((char)b));
            tgt.write(b);
        }
    }




}
