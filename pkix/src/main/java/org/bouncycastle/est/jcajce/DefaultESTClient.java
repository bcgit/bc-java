package org.bouncycastle.est.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.est.ESTClient;
import org.bouncycastle.est.ESTClientSourceProvider;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTRequest;
import org.bouncycastle.est.ESTRequestBuilder;
import org.bouncycastle.est.ESTResponse;
import org.bouncycastle.est.Source;
import org.bouncycastle.util.Properties;

class DefaultESTClient
    implements ESTClient
{
    private static final Charset utf8 = Charset.forName("UTF-8");
    private static byte[] CRLF = new byte[]{'\r', '\n'};
    private final ESTClientSourceProvider sslSocketProvider;

    public DefaultESTClient(ESTClientSourceProvider sslSocketProvider)
    {
        this.sslSocketProvider = sslSocketProvider;
    }

    private static void writeLine(OutputStream os, String s)
        throws IOException
    {
        os.write(s.getBytes());
        os.write(CRLF);
    }

    public ESTResponse doRequest(ESTRequest req)
        throws IOException
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
        throws IOException
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

                ESTRequestBuilder requestBuilder = new ESTRequestBuilder(response.getOriginalRequest());
                if (loc.startsWith("http"))
                {
                    URL original = response.getOriginalRequest().getURL();
                    URL target = new URL(loc);
                    // The rebuilt request carries the original request's headers (including any
                    // Authorization) and body (e.g. the enrolment CSR). Following a redirect to a
                    // different origin would replay those credentials/data to an attacker-chosen
                    // host, so cross-origin redirects are refused; only same-origin ones are followed.
                    if (!isSameOrigin(original, target))
                    {
                        throw new ESTException("refusing cross-origin redirect from " + original.getHost() + " to " + target.getHost());
                    }
                    redirectingRequest = requestBuilder.withURL(target).build();
                }
                else
                {
                    URL u = response.getOriginalRequest().getURL();
                    redirectingRequest = requestBuilder.withURL(new URL(u.getProtocol(), u.getHost(), u.getPort(), loc)).build();
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

    private static boolean isSameOrigin(URL a, URL b)
    {
        if (!a.getProtocol().equalsIgnoreCase(b.getProtocol())
            || !a.getHost().equalsIgnoreCase(b.getHost()))
        {
            return false;
        }

        int portA = a.getPort() == -1 ? a.getDefaultPort() : a.getPort();
        int portB = b.getPort() == -1 ? b.getDefaultPort() : b.getPort();

        return portA == portB;
    }

    public ESTResponse performRequest(ESTRequest c)
        throws IOException
    {


        ESTResponse res = null;
        Source socketSource = null;
        try
        {
            socketSource = sslSocketProvider.makeSource(c.getURL().getHost(), c.getURL().getPort());
            if (c.getListener() != null)
            {
                c = c.getListener().onConnection(socketSource, c);
            }

            //  socketSource = new SSLSocketSource((SSLSocket)sock);

            OutputStream os = null;

            Set<String> opts = Properties.asKeySet("org.bouncycastle.debug.est");
            if (opts.contains("output") ||
                opts.contains("all"))
            {
                os = new PrintingOutputStream(socketSource.getOutputStream());
            }
            else
            {
                os = socketSource.getOutputStream();
            }

            String req = c.getURL().getPath() + ((c.getURL().getQuery() != null) ? c.getURL().getQuery() : "");

            ESTRequestBuilder rb = new ESTRequestBuilder(c);

            Map<String, String[]> headers = c.getHeaders();

            if (!headers.containsKey("Connection"))
            {
                rb.addHeader("Connection",  "close" );
            }

            // Replace host header.
            URL u = c.getURL();
            if (u.getPort() > -1)
            {
                rb.setHeader("Host", String.format("%s:%d", u.getHost(), u.getPort()));
            }
            else
            {
                rb.setHeader("Host", u.getHost());
            }


            ESTRequest rc = rb.build();

            writeLine(os, rc.getMethod() + " " + req + " HTTP/1.1");


            for (Iterator it = rc.getHeaders().entrySet().iterator(); it.hasNext();)
            {
                Map.Entry<String, String[]> ent = (Map.Entry<String, String[]>)it.next();
                String[] vs = (String[])ent.getValue();

                for (int i = 0; i != vs.length; i++)
                {
                    writeLine(os, ent.getKey() + ": " + vs[i]);
                }
            }

            os.write(CRLF);
            os.flush();

            rc.writeData(os);

            os.flush();

            if (rc.getHijacker() != null)
            {
                res = rc.getHijacker().hijack(rc, socketSource);
                return res;
            }
            else
            {
                res = new ESTResponse(rc, socketSource);
            }

            return res;

        }
        finally
        {
            // Close only if response not generated.
            if (socketSource != null && res == null)
            {
                socketSource.close();
            }
        }

    }

    private static class PrintingOutputStream
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
            // -DM System.out.println
            System.out.print(String.valueOf((char)b));
            tgt.write(b);
        }
    }
}
