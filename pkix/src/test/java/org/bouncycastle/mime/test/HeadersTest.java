package org.bouncycastle.mime.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.util.Strings;

/**
 * Headers(InputStream, String) declares IOException and is what BasicMimeParser and
 * SMimeParserProvider use, but the header block it parses is raw message bytes and several fields
 * were used without a check, so malformed input escaped as an unchecked exception: a header line
 * with no ':' gave StringIndexOutOfBoundsException from substring(0, -1), a multipart Content-Type
 * with no boundary parameter gave a NullPointerException, and a one-character boundary gave
 * StringIndexOutOfBoundsException from an unconditional quoted-string strip.
 * <p>
 * That strip was also wrong for a bare boundary, which RFC 2046 sec. 5.1.1 permits: it silently
 * turned boundary=abcdef into "bcde", so the body's delimiters never matched. The sibling
 * Headers(String, String) constructor had been corrected for that and the other copy had not, which
 * is why all three constructors now share one implementation.
 */
public class HeadersTest
    extends TestCase
{
    private Headers fromStream(String mime)
        throws IOException
    {
        return new Headers(new ByteArrayInputStream(Strings.toByteArray(mime)), "7bit");
    }

    private void assertStreamRejects(String label, String mime)
    {
        try
        {
            fromStream(mime);
            fail(label + ": accepted");
        }
        catch (IOException e)
        {
            // expected - the declared exception, not an unchecked one
        }
        catch (RuntimeException e)
        {
            fail(label + ": unchecked " + e.getClass().getName() + ": " + e.getMessage());
        }
    }

    public void testHeaderLineWithoutDelimiterRejected()
    {
        assertStreamRejects("no colon", "NoColonHeader\r\n\r\nbody");
        assertStreamRejects("no colon after a good header",
            "Content-Type: text/plain\r\nNoColonHeader\r\n\r\nbody");
    }

    public void testMultipartWithoutBoundaryRejected()
    {
        assertStreamRejects("no boundary", "Content-Type: multipart/mixed\r\n\r\n");
        assertStreamRejects("empty boundary", "Content-Type: multipart/mixed; boundary=\r\n\r\n");
        assertStreamRejects("boundary is two quotes", "Content-Type: multipart/mixed; boundary=\"\"\r\n\r\n");
    }

    /**
     * A boundary of a single quote character is not valid bcharsnospace, but the point here is only
     * that it no longer reaches substring(1, 0): it is taken as the one-character boundary it looks
     * like, and fails later against the body like any other boundary that does not match. Policing
     * the boundary character set is a separate question from the unchecked exception.
     */
    public void testBoundaryOfOneQuoteIsNotStripped()
        throws IOException
    {
        assertEquals("\"", fromStream("Content-Type: multipart/mixed; boundary=\"\r\n\r\n").getBoundary());
    }

    public void testMalformedContentTypeParameterRejected()
    {
        // was IllegalArgumentException, which is unchecked, from a constructor declaring IOException
        assertStreamRejects("parameter with no =", "Content-Type: multipart/mixed; junk\r\n\r\n");
    }

    public void testBoundaryQuotedAndBare()
        throws IOException
    {
        // RFC 2046 sec. 5.1.1: bcharsnospace, optionally as a quoted-string
        assertEquals("abcdef", fromStream("Content-Type: multipart/mixed; boundary=\"abcdef\"\r\n\r\n").getBoundary());
        assertEquals("abcdef", fromStream("Content-Type: multipart/mixed; boundary=abcdef\r\n\r\n").getBoundary());
        assertEquals("x", fromStream("Content-Type: multipart/mixed; boundary=x\r\n\r\n").getBoundary());
        assertEquals("a b", fromStream("Content-Type: multipart/mixed; boundary=\"a b\"\r\n\r\n").getBoundary());
    }

    /**
     * The two constructors that cannot declare IOException report the same conditions as an
     * IllegalArgumentException carrying the message, rather than as a null dereference.
     */
    public void testUncheckedConstructorsReportTheSameConditions()
    {
        try
        {
            new Headers("multipart/mixed", "base64");
            fail("no boundary accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("no boundary parameter for multipart content type", e.getMessage());
            assertTrue(e.getCause() instanceof IOException);
        }

        List lines = new ArrayList();
        lines.add("NoColonHeader");
        try
        {
            new Headers(lines, "7bit");
            fail("header line with no delimiter accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("header line has no ':' delimiter", e.getMessage());
        }
    }

    /**
     * Headers(String, String) assigned its content type to the constructor parameter, which shadows
     * the field of the same name, so getContentType() returned null for every instance built that
     * way - including the one ESTService.handleEnrollResponse builds for a multipart/mixed enrol
     * response.
     */
    public void testContentTypeSetByStringConstructor()
    {
        Headers h = new Headers("multipart/mixed; boundary=\"abcdef\"", "base64");

        assertEquals("multipart/mixed", h.getContentType());
        assertTrue(h.isMultipart());
        assertEquals("abcdef", h.getBoundary());
        assertEquals("base64", h.getContentTransferEncoding());

        Headers plain = new Headers("text/plain", "7bit");

        assertEquals("text/plain", plain.getContentType());
        assertFalse(plain.isMultipart());
        assertNull(plain.getBoundary());
    }

    /** The compatibility assertion: well-formed header blocks are unchanged. */
    public void testWellFormedHeadersUnchanged()
        throws IOException
    {
        Headers h = fromStream("Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\";"
            + " boundary=\"----=_Part_1\"\r\n"
            + "Content-Transfer-Encoding: base64\r\n"
            + "Subject: a folded\r\n subject line\r\n"
            + "\r\nbody");

        assertEquals("multipart/signed", h.getContentType());
        assertTrue(h.isMultipart());
        assertEquals("----=_Part_1", h.getBoundary());
        assertEquals("base64", h.getContentTransferEncoding());
        // only the boundary is unquoted; other parameter values are returned as they appear
        assertEquals("\"application/pkcs7-signature\"", h.getContentTypeAttributes().get("protocol"));
        assertEquals("a foldedsubject line", h.getValues("Subject")[0]);

        Headers noContentType = fromStream("Subject: hello\r\n\r\nbody");

        assertEquals("text/plain", noContentType.getContentType());
        assertFalse(noContentType.isMultipart());
        assertEquals("7bit", noContentType.getContentTransferEncoding());
    }
}
