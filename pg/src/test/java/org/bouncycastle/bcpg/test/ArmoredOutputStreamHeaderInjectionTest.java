package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Hashtable;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

/**
 * Regression test for ASCII-armor header injection via a bare carriage return. Armor header
 * sanitization split and rejected on LF only, so a CR embedded in a header value (e.g. a parsed
 * User-ID re-armored as a Comment) survived into a single header line and could forge an armor
 * boundary or an extra header for a reader that treats CR as end-of-line.
 */
public class ArmoredOutputStreamHeaderInjectionTest
    extends AbstractPacketTest
{
    public String getName()
    {
        return "ArmoredOutputStreamHeaderInjectionTest";
    }

    public void performTest()
        throws Exception
    {
        byte[] data = Strings.toByteArray("the quick brown fox");

        // A Comment value carrying a bare CR followed by a forged armor tail. Splitting on CR turns
        // it into separate, well-formed "Comment:" headers, so the armor re-parses cleanly. Without
        // the fix the CR survives into one header line and BouncyCastle's own reader -- which treats
        // a lone CR as end-of-line -- rejects the armor as malformed (a round-trip denial of service).
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ArmoredOutputStream aOut = ArmoredOutputStream.builder()
            .addComment("note\r-----END PGP MESSAGE-----")
            .build(bOut);
        aOut.write(data, 0, data.length);
        aOut.close();

        ArmoredInputStream aIn = new ArmoredInputStream(new ByteArrayInputStream(bOut.toByteArray()));
        byte[] recovered = Streams.readAll(aIn);
        aIn.close();

        isTrue("armored round-trip with an embedded CR in a comment failed",
            Arrays.areEqual(data, recovered));

        // A singleton header value containing a bare CR must be rejected, as one containing LF is.
        try
        {
            ArmoredOutputStream.builder().setVersion("v\rInjected: forged").build(new ByteArrayOutputStream());
            fail("CR in singleton armor header value accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        // The deprecated setHeader(...) stores the value raw and emits it through the same
        // writeHeaderEntry chokepoint as the Builder. A LF in the value used to inject a second
        // parsed armor header; it must now be rejected when the header block is flushed on first
        // write. This is the path finding #25's proof exercised.
        try
        {
            ArmoredOutputStream injected = new ArmoredOutputStream(new ByteArrayOutputStream());
            injected.setHeader("Comment", "hello\nInjected: smuggled-header");
            injected.write(0x01);
            fail("LF in deprecated setHeader value accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                "armor header must not contain CR/LF".equals(e.getMessage()));
        }

        // The Hashtable constructor is the other raw, non-deprecated path through the chokepoint;
        // a bare CR in a value must be rejected there too.
        Hashtable<String, String> rawHeaders = new Hashtable<String, String>();
        rawHeaders.put(ArmoredOutputStream.COMMENT_HDR, "hello\r-----END PGP MESSAGE-----");
        try
        {
            ArmoredOutputStream injected = new ArmoredOutputStream(new ByteArrayOutputStream(), rawHeaders);
            injected.write(0x01);
            fail("CR in Hashtable-constructor header value accepted");
        }
        catch (IllegalArgumentException e)
        {
            isTrue("unexpected message: " + e.getMessage(),
                "armor header must not contain CR/LF".equals(e.getMessage()));
        }
    }

    public static void main(String[] args)
    {
        runTest(new ArmoredOutputStreamHeaderInjectionTest());
    }
}
