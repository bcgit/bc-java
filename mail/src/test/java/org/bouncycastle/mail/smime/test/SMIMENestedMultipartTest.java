package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import junit.framework.TestCase;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.mail.smime.CMSProcessableBodyPartInbound;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.mail.smime.handlers.multipart_signed;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * The signed half of an inbound multipart/signed is entirely sender-controlled, and RFC 5751 puts no
 * limit on how deeply it may nest multipart content. Two independent recursions walked it with no
 * depth counter - SMIMEUtil.outputBodyPart, reached from SMIMESigned / SMIMESignedParser /
 * SignedMailValidator through CMSProcessableBodyPartInbound.write, and the separate one in the
 * multipart/signed content handler reached from JavaMail's writeTo - so a few hundred KB of nested
 * mail exhausted the thread stack. Each level costs a frame here plus the frames JavaMail spends
 * resolving the part, so StackOverflowError arrived at a depth of roughly 2500 on a default 1MB
 * stack. Both now stop at Properties.MIME_MAX_DEPTH, default 64; real mail nests two or three deep.
 */
public class SMIMENestedMultipartTest
    extends TestCase
{
    /**
     * Raw MIME nesting multipart/mixed to the given depth with a text/plain leaf, i.e. what arrives
     * off the wire rather than something built through the JavaMail API.
     */
    private static byte[] nestedMultipart(int depth)
    {
        StringBuffer head = new StringBuffer();
        StringBuffer tail = new StringBuffer();

        for (int i = 0; i != depth; i++)
        {
            String b = "b" + i;
            head.append("Content-Type: multipart/mixed; boundary=\"").append(b).append("\"\r\n\r\n");
            head.append("--").append(b).append("\r\n");
            tail.insert(0, "\r\n--" + b + "--\r\n");
        }

        head.append("Content-Type: text/plain\r\n\r\nleaf\r\n");

        return Strings.toByteArray(head.toString() + tail.toString());
    }

    private static MimeBodyPart bodyPart(int depth)
        throws MessagingException
    {
        return new MimeBodyPart(new ByteArrayInputStream(nestedMultipart(depth)));
    }

    /**
     * CMSProcessableBodyPartInbound.write declares both IOException and CMSException and wraps the
     * MessagingException in the latter, so a checked exception is what a caller sees either way.
     */
    private void assertRejected(int depth)
        throws Exception
    {
        try
        {
            new CMSProcessableBodyPartInbound(bodyPart(depth)).write(sink());
            fail("nesting past the cap accepted at depth " + depth);
        }
        catch (StackOverflowError e)
        {
            fail("recursed to StackOverflowError at depth " + depth);
        }
        catch (CMSException e)
        {
            assertTrue(e.getMessage(), e.getMessage().indexOf("nesting depth") >= 0);
        }
    }

    private static OutputStream sink()
    {
        return new OutputStream()
        {
            public void write(int b)
            {
            }
        };
    }

    public void testDefaultDepthIs64()
    {
        assertEquals(64, SMIMEUtil.getMaxDepth());
    }

    /**
     * 100 levels is only ~6KB and does not come close to overflowing a stack - before the cap it
     * simply succeeded, which is what makes it a deterministic check on the bound rather than on the
     * machine's stack size.
     */
    public void testCanonicaliserStopsAtTheCap()
        throws Exception
    {
        assertRejected(100);
    }

    /** The second recursion, over the same content, reached through the content handler. */
    public void testContentHandlerStopsAtTheCap()
        throws Exception
    {
        MimeMultipart mp = new MimeMultipart(bodyPart(100).getDataHandler().getDataSource());

        try
        {
            new multipart_signed().writeTo(mp, "multipart/signed", sink());
            fail("nesting past the cap accepted");
        }
        catch (StackOverflowError e)
        {
            fail("recursed to StackOverflowError");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().indexOf("nesting depth") >= 0);
        }
    }

    /**
     * The depth that used to overflow. Post-cap this never descends past 65 levels, so it is cheap;
     * the assertion is that no Error escapes a path declaring IOException.
     */
    public void testDepthThatUsedToOverflowTheStack()
        throws Exception
    {
        assertRejected(3000);
    }

    /** The compatibility assertion: nesting of the depth real mail uses is unaffected. */
    public void testOrdinaryNestingStillCanonicalises()
        throws Exception
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        new CMSProcessableBodyPartInbound(bodyPart(3)).write(bOut);

        byte[] out = bOut.toByteArray();

        assertTrue(out.length != 0);
        assertTrue(Strings.fromByteArray(out).indexOf("leaf") >= 0);
    }

    public void testCapIsConfigurable()
        throws Exception
    {
        System.setProperty(Properties.MIME_MAX_DEPTH, "8");
        try
        {
            assertEquals(8, SMIMEUtil.getMaxDepth());

            // still fine at the ordinary depth
            new CMSProcessableBodyPartInbound(bodyPart(3)).write(sink());

            assertRejected(20);
        }
        finally
        {
            System.getProperties().remove(Properties.MIME_MAX_DEPTH);
        }
    }
}
