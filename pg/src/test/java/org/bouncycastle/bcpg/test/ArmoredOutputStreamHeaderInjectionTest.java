package org.bouncycastle.bcpg.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

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
    }

    public static void main(String[] args)
    {
        runTest(new ArmoredOutputStreamHeaderInjectionTest());
    }
}
