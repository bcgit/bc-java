package org.bouncycastle.est.jcajce;


import org.bouncycastle.est.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class DefaultESTClient
    implements ESTClient
{
    private final ESTClientSourceProvider sslSocketProvider;
    private static final Charset utf8 = Charset.forName("UTF-8");
    private static byte[] CRLF = new byte[]{'\r', '\n'};

    public DefaultESTClient(ESTClientSourceProvider sslSocketProvider)
    {
        this.sslSocketProvider = sslSocketProvider;
    }


    public ESTResponse doRequest(ESTRequest req)
        throws Exception
    {
        ESTResponse resp = null;
        ESTRequest r = req;
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

    protected ESTRequest redirectURL(ESTResponse response)
        throws Exception
    {
        ESTRequest redirectingRequest = null;

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
                    URL u = response.getOriginalRequest().getUrl();
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


    public ESTResponse performRequest(ESTRequest c)
        throws Exception
    {
        c.setEstClient(this);
        Socket sock = null;
        ESTResponse res = null;
        Source socketSource = null;
        try
        {

            sock = new Socket(c.getUrl().getHost(), c.getUrl().getPort());
            socketSource = sslSocketProvider.wrapSocket(sock, c.getUrl().getHost(), c.getUrl().getPort());

          //  socketSource = new SSLSocketSource((SSLSocket)sock);

            OutputStream os = new PrintingOutputStream(socketSource.getOutputStream());
//            InputStream in = new PrintingInputStream(sock.getInputStream());

            String req = c.getUrl().getPath() + ((c.getUrl().getQuery() != null) ? c.getUrl().getQuery() : "");

            // Replace host header.

            c.getHeaders().put("Host", Collections.singletonList(c.getUrl().getHost()));
            writeLine(os, c.getMethod() + " " + req + " HTTP/1.1");


            for (Map.Entry<String, List<String>> ent : c.getHeaders().entrySet())
            {
                for (String v : ent.getValue())
                {
                    writeLine(os, ent.getKey() + ": " + v);
                }
            }

            os.write(CRLF);
            os.flush();
            if (c.getWriter() != null)
            {
                c.getWriter().ready(os);
            }
            os.flush();

            if (c.getHijacker() != null)
            {
                res = c.getHijacker().hijack(c, socketSource);
                return res;
            }
            else
            {
                res = new ESTResponse(c, socketSource);
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
