package org.bouncycastle.oer.test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.util.Arrays;

/**
 * Bounds checks in the OER decoder against hostile input: recursion depth, SEQUENCE-OF element
 * count, and open-type/extension allocation.
 */
public class OERInputStreamLimitTest
    extends TestCase
{
    /**
     * A nesting deeper than the decoder's cap must be rejected with a bounded IOException rather
     * than recursing until the JVM throws StackOverflowError. (The depth here, 320, comfortably
     * exceeds the 256 cap while staying well short of an actual stack overflow, so before the fix
     * the parse simply succeeded and this test failed - after the fix it throws.)
     */
    public void testNestingDepthBounded()
        throws Exception
    {
        OERDefinition.Builder b = OERDefinition.bool();
        for (int i = 0; i < 320; i++)
        {
            b = OERDefinition.seq(b);
        }
        Element schema = b.build();

        // 320 nested SEQUENCEs (each with a single explicit child consume no preamble bytes) then a
        // single BOOLEAN byte: a one-byte payload that drives 320 levels of recursive descent.
        byte[] payload = new byte[]{0x00};

        try
        {
            OERInputStream.parse(payload, schema);
            fail("over-deep nesting should be rejected");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("nesting depth"));
        }
    }

    /**
     * An extension the decoder has no definition for is skipped by length. That length is
     * attacker-supplied and bounded only by 2^31-1, and it used to be consumed one
     * {@code in.read()} at a time, ignoring the -1 that signals end of stream: a handful of bytes
     * declaring a huge extension spun a CPU for as long as the length said. Worse, with the
     * presence bit set and nothing following, the parse then <em>returned normally</em>, so the
     * burn left no trace. It must now fail at the real end of input.
     */
    public void testUnknownExtensionSkipBounded()
        throws Exception
    {
        // a SEQUENCE that knows a BOOLEAN and admits the possibility of extensions it cannot parse
        Element schema = OERDefinition.seq(
            OERDefinition.bool(),
            OERDefinition.extension()
        ).build();

        // preamble with the extension bit set, the known BOOLEAN, then a one-byte presence
        // bitmap with one extension present, whose length says 0x7FFFFFF0 with no body behind it
        byte[] payload = new byte[]{
            (byte)0x80,                                     // preamble: extension flag
            0x00,                                           // the BOOLEAN
            0x02, 0x07, (byte)0x80,                         // presence list: 1 byte, 7 unused bits, bit set
            (byte)0x84, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xF0   // extension length 0x7FFFFFF0
        };

        long start = System.currentTimeMillis();
        try
        {
            OERInputStream.parse(payload, schema);
            fail("truncated unknown extension should be rejected");
        }
        catch (IOException e)
        {
            // expected - what matters is that it returns at all, and promptly
        }

        long elapsed = System.currentTimeMillis() - start;
        assertTrue("skipping a truncated unknown extension took " + elapsed + "ms", elapsed < 5000);
    }

    /**
     * A SEQUENCE-OF count beyond the decoder's allocation ceiling is rejected before the parse
     * loop; a count within it over a short input stops at the first element that is not there,
     * so neither drives ~count iterations of allocation.
     */
    public void testSeqOfCountBounded()
        throws Exception
    {
        Element schema = OERDefinition.seqof(OERDefinition.integer(0, 255)).build();

        // Count length-determinant 0x04, count = 0x7FFFFFFF, past the default 1 MiB ceiling
        try
        {
            OERInputStream.parse(new byte[]{0x04, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF}, schema);
            fail("oversized SEQUENCE OF count should be rejected");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("out of range"));
        }

        // a lower ceiling moves the line
        try
        {
            new OERInputStream(new ByteArrayInputStream(new byte[]{0x01, 0x11}), 16).parse(schema);
            fail("SEQUENCE OF count over the configured ceiling should be rejected");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage(), e.getMessage().contains("out of range"));
        }
        assertEquals(16, ((ASN1Sequence)new OERInputStream(new ByteArrayInputStream(
            Arrays.concatenate(new byte[]{0x01, 0x10}, new byte[16])), 16).parse(schema)).size());

        // count 100000 (3-byte count) with no element bytes at all: fails at the first element
        long start = System.currentTimeMillis();
        try
        {
            OERInputStream.parse(new byte[]{0x03, 0x01, (byte)0x86, (byte)0xA0}, schema);
            fail("truncated SEQUENCE OF should be rejected");
        }
        catch (EOFException e)
        {
            // expected
        }
        assertTrue(System.currentTimeMillis() - start < 5000);
    }

    /**
     * The count used to be bounded by InputStream.available(), which is an estimate of the bytes
     * readable without blocking: 0 from the base class and from wrappers such as CipherInputStream,
     * so a valid SEQUENCE OF arriving through such a stream was rejected as out of range.
     */
    public void testSeqOfDecodesFromStreamReportingNothingAvailable()
        throws Exception
    {
        Element schema = OERDefinition.seqof(OERDefinition.integer(0, 255)).build();
        byte[] payload = new byte[]{0x01, 0x03, 0x0A, 0x0B, 0x0C};

        InputStream nothingAvailable = new FilterInputStream(new ByteArrayInputStream(payload))
        {
            public int available()
            {
                return 0;
            }
        };

        ASN1Sequence decoded = (ASN1Sequence)new OERInputStream(nothingAvailable).parse(schema);
        assertEquals(3, decoded.size());
        assertTrue(ASN1Integer.getInstance(decoded.getObjectAt(2)).hasValue(0x0C));
    }
}
