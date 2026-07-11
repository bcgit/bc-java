package org.bouncycastle.mime.test;

import junit.framework.TestCase;

import org.bouncycastle.mime.smime.SMIMEEnvelopedWriter;
import org.bouncycastle.mime.smime.SMIMESignedWriter;

public class SMIMEWriterHeaderInjectionTest
    extends TestCase
{
    private static final String INJECT = "Invoice\r\nBcc: attacker@example.com";

    public void testEnvelopedRejectsCRLFInValue()
    {
        try
        {
            new SMIMEEnvelopedWriter.Builder().withHeader("Subject", INJECT);
            fail("header value with a line separator accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("header name or value must not contain a line separator", e.getMessage());
        }
    }

    public void testEnvelopedRejectsCRLFInName()
    {
        try
        {
            new SMIMEEnvelopedWriter.Builder().withHeader("X-Evil\r\nBcc: attacker@example.com", "x");
            fail("header name with a line separator accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("header name or value must not contain a line separator", e.getMessage());
        }
    }

    public void testSignedRejectsCRLFInValue()
    {
        try
        {
            new SMIMESignedWriter.Builder().withHeader("Subject", INJECT);
            fail("header value with a line separator accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("header name or value must not contain a line separator", e.getMessage());
        }
    }

    public void testBareLineFeedRejected()
    {
        try
        {
            new SMIMESignedWriter.Builder().withHeader("Subject", "a\nBcc: attacker@example.com");
            fail("header value with a bare line feed accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("header name or value must not contain a line separator", e.getMessage());
        }
    }

    public void testCleanHeadersAccepted()
    {
        new SMIMEEnvelopedWriter.Builder().withHeader("Subject", "Quarterly report");
        new SMIMESignedWriter.Builder().withHeader("X-Custom", "a plain value");
    }
}
