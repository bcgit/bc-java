package org.bouncycastle.est.http;


import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
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

    public ESTHttpResponse doRequest(ESTHttpRequest c)
        throws Exception
    {
        Socket sock = null;
        ESTHttpResponse res = null;
        try
        {
            sock = new Socket(c.url.getHost(), c.url.getPort());
            sock = sslSocketProvider.wrapSocket(sock, c.url.getHost(), c.url.getPort());


            OutputStream os = sock.getOutputStream();
            InputStream in = sock.getInputStream();
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

            res = new ESTHttpResponse(c, sock);
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


}
