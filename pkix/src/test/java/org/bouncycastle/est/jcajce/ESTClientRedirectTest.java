package org.bouncycastle.est.jcajce;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URL;

import javax.net.ssl.SSLSession;

import junit.framework.TestCase;
import org.bouncycastle.est.ESTException;
import org.bouncycastle.est.ESTRequest;
import org.bouncycastle.est.ESTRequestBuilder;
import org.bouncycastle.est.ESTResponse;
import org.bouncycastle.est.Source;

/**
 * Regression test: DefaultESTClient.redirectURL must not follow a 3xx redirect to a different
 * origin (host/port/scheme), since the rebuilt request carries the original request's headers
 * (including any Authorization) and body (the enrolment CSR).
 */
public class ESTClientRedirectTest
    extends TestCase
{
    public void testCrossOriginRedirectRefused()
        throws Exception
    {
        DefaultESTClient client = new DefaultESTClient(null);

        ESTRequest original = new ESTRequestBuilder(
            "GET", new URL("https://good.example.com:8443/.well-known/est/cacerts")).build();

        // Redirect to a different host - must be refused.
        ESTResponse crossHost = response(original, "https://evil.example.com:8443/.well-known/est/cacerts");
        try
        {
            client.redirectURL(crossHost);
            fail("cross-host redirect should be refused");
        }
        catch (ESTException e)
        {
            assertTrue(e.getMessage().startsWith("refusing cross-origin redirect"));
        }

        // Redirect to a different port - must be refused.
        ESTResponse crossPort = response(original, "https://good.example.com:9443/.well-known/est/cacerts");
        try
        {
            client.redirectURL(crossPort);
            fail("cross-port redirect should be refused");
        }
        catch (ESTException e)
        {
            assertTrue(e.getMessage().startsWith("refusing cross-origin redirect"));
        }

        // Redirect downgrading the scheme - must be refused.
        ESTResponse crossScheme = response(original, "http://good.example.com:8443/.well-known/est/cacerts");
        try
        {
            client.redirectURL(crossScheme);
            fail("scheme-downgrade redirect should be refused");
        }
        catch (ESTException e)
        {
            assertTrue(e.getMessage().startsWith("refusing cross-origin redirect"));
        }
    }

    public void testSameOriginRedirectFollowed()
        throws Exception
    {
        DefaultESTClient client = new DefaultESTClient(null);

        ESTRequest original = new ESTRequestBuilder(
            "GET", new URL("https://good.example.com:8443/.well-known/est/cacerts")).build();

        // Same origin, different path - must be followed.
        ESTResponse sameOrigin = response(original, "https://good.example.com:8443/.well-known/est/csrattrs");
        ESTRequest redirected = client.redirectURL(sameOrigin);
        assertNotNull("same-origin redirect should be followed", redirected);
        assertEquals("good.example.com", redirected.getURL().getHost());
        assertEquals("/.well-known/est/csrattrs", redirected.getURL().getPath());
    }

    private static ESTResponse response(ESTRequest original, String location)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PrintWriter pw = new PrintWriter(bOut);
        pw.print("HTTP/1.1 302 Found\r\n");
        pw.print("Location: " + location + "\r\n");
        pw.print("Content-Length: 0\r\n");
        pw.print("\r\n");
        pw.flush();

        return new ESTResponse(original, mockSource(new ByteArrayInputStream(bOut.toByteArray())));
    }

    private static Source<SSLSession> mockSource(final InputStream data)
    {
        return new Source<SSLSession>()
        {
            public InputStream getInputStream()
                throws IOException
            {
                return data;
            }

            public OutputStream getOutputStream()
                throws IOException
            {
                return null;
            }

            public SSLSession getSession()
            {
                return null;
            }

            public void close()
                throws IOException
            {
            }
        };
    }
}
