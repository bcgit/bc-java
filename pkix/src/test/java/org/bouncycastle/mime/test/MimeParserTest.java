package org.bouncycastle.mime.test;

import java.io.ByteArrayInputStream;

import junit.framework.TestCase;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.util.Strings;

public class MimeParserTest
    extends TestCase
{
    public void testMixtureOfHeaders()
        throws Exception
    {

        String parts[] = new String[]{
            "Received", "from mr11p26im-asmtp003.me.com (mr11p26im-asmtp003.me.com [17.110.86.110]) " +
            "by tauceti.org.au (Our Mail Server) with ESMTP (TLS) id 23294071-1879654 " +
            "for <megan@cryptoworkshop.com>; Fri, 29 Jun 2018 14:52:26 +1000\n",
            "Return-Path", " <pogobot@icloud.com>\n",
            "X-Verify-SMTP", " Host 17.110.86.110 sending to us was not listening\r\n"
        };


        String values = parts[0] + ":" + parts[1] + parts[2] + ":" + parts[3] + parts[4] + ":" + parts[5] + "\r\n";

        Headers headers = new Headers(new ByteArrayInputStream(Strings.toByteArray(values)), "7bit");

        for (int t = 0; t < parts.length; t += 2)
        {
            TestCase.assertEquals("Part " + t, parts[t + 1].trim(), headers.getValues(parts[t])[0]);
        }

    }

    public void testEndOfHeaders()
        throws Exception
    {
        String values = "Foo: bar\r\n\r\n";

        Headers headers = new Headers(new ByteArrayInputStream(Strings.toByteArray(values)), "7bit");

        assertEquals("bar", headers.getValues("Foo")[0]);
    }
}
