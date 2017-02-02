package org.bouncycastle.pkix.est;


import java.io.ByteArrayInputStream;
import java.net.URL;

import org.bouncycastle.est.http.DigestAuth;
import org.bouncycastle.est.http.ESTHttpRequest;
import org.bouncycastle.est.http.ESTHttpResponse;
import org.bouncycastle.util.test.SimpleTest;
import org.junit.Test;

public class TestDigestAuth
    extends SimpleTest
{

    public String getName()
    {
        return "TestDigestAuth";
    }

    public void performTest()
        throws Exception
    {
        ESTTestUtils.runJUnit(TestEnroll.class);
    }

    @Test
    public void testDigestAuth()
        throws Exception
    {
        String msg = "HTTP/1.0 401 Unauthorized\n" +
            "Server: HTTPd/0.9\n" +
            "Date: Sun, 10 Apr 2014 20:26:47 GMT\n" +
            "WWW-Authenticate: Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\n" +
            "Content-Type: text/html\n" +
            "Content-Length: 153\n" +
            "\n" +
            "<!DOCTYPE html>\n" +
            "<html>\n" +
            "  <head>\n" +
            "    <meta charset=\"UTF-8\" />\n" +
            "    <title>Error</title>\n" +
            "  </head>\n" +
            "  <body>\n" +
            "    <h1>401 Unauthorized.</h1>\n" +
            "  </body>\n" +
            "</html>";


        ESTHttpResponse resp = new ESTHttpResponse(new ESTHttpRequest("GET", new URL("http://foo.com/dir/index.html")), new ByteArrayInputStream(msg.getBytes()));


        ESTHttpResponse r = (new DigestAuth("Mufasa", "Circle Of Life")
        {
            public ESTHttpResponse _doDigestFunction(ESTHttpResponse res)
                throws Exception
            {
                return doDigestFunction(res);
            }
        })._doDigestFunction(resp);


        System.out.println(r.getHeader("Authorization"));
    }


    public static void main(String[] args)
        throws Exception
    {
        runTest(new TestDigestAuth());
    }

}
