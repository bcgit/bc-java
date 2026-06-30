package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Tests for {@code long} definite-length support in the streaming parser
 * (ASN1StreamParser / DefiniteLengthInputStream) — content beyond the size of
 * a Java array can be traversed and drained, while materialization stays
 * bounded by what an array can hold (github #1482).
 */
public class LongDefiniteLengthParserTest
    extends SimpleTest
{
    private static final long BIG = (1L << 31) + 12345;    // just past the byte[] limit
    private static final byte FILL = (byte)0xA5;

    public String getName()
    {
        return "LongDefiniteLengthParser";
    }

    public void performTest()
        throws Exception
    {
        testBigPrimitiveOctetStringStreams();
        testBigConstructedSequenceTraverses();
        testBigPrimitiveMaterializationRejected();
        testBigTruncationDetected();
        testOverlongLengthRejected();
    }

    private void testBigPrimitiveOctetStringStreams()
        throws Exception
    {
        ASN1StreamParser parser = new ASN1StreamParser(
            new SequenceInputStream(new ByteArrayInputStream(header(0x04, BIG)), new FillStream(BIG)));

        ASN1OctetStringParser octets = (ASN1OctetStringParser)parser.readObject();
        isTrue("octet content count", BIG == drain(octets.getOctetStream()));
        isTrue("nothing after octets", null == parser.readObject());
    }

    private void testBigConstructedSequenceTraverses()
        throws Exception
    {
        // SEQUENCE { OCTET STRING (BIG octets), INTEGER 5 }
        byte[] intEnc = new ASN1Integer(5).getEncoded();
        byte[] octHeader = header(0x04, BIG);
        long seqBody = octHeader.length + BIG + intEnc.length;

        ByteArrayOutputStream prefix = new ByteArrayOutputStream();
        prefix.write(header(0x30, seqBody));
        prefix.write(octHeader);

        InputStream in = new SequenceInputStream(
            new SequenceInputStream(new ByteArrayInputStream(prefix.toByteArray()), new FillStream(BIG)),
            new ByteArrayInputStream(intEnc));

        ASN1StreamParser parser = new ASN1StreamParser(in);
        ASN1SequenceParser seq = (ASN1SequenceParser)parser.readObject();

        ASN1OctetStringParser octets = (ASN1OctetStringParser)seq.readObject();
        isTrue("nested octet content count", BIG == drain(octets.getOctetStream()));

        ASN1Encodable next = seq.readObject();
        isTrue("trailing INTEGER recovered", new ASN1Integer(5).equals(next.toASN1Primitive()));
        isTrue("sequence exhausted", null == seq.readObject());
    }

    private void testBigPrimitiveMaterializationRejected()
        throws Exception
    {
        // an INTEGER cannot be streamed; a beyond-array length must be
        // rejected up front rather than attempted.
        final ASN1StreamParser parser = new ASN1StreamParser(
            new SequenceInputStream(new ByteArrayInputStream(header(0x02, BIG)), new FillStream(BIG)));

        try
        {
            parser.readObject();
            fail("oversize INTEGER not rejected");
        }
        catch (ASN1Exception e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("out of bounds length found") >= 0);
        }
    }

    private void testBigTruncationDetected()
        throws Exception
    {
        // declared BIG octets, supplied 100
        ASN1StreamParser parser = new ASN1StreamParser(
            new SequenceInputStream(new ByteArrayInputStream(header(0x04, BIG)), new FillStream(100)));

        ASN1OctetStringParser octets = (ASN1OctetStringParser)parser.readObject();
        try
        {
            drain(octets.getOctetStream());
            fail("truncation not detected");
        }
        catch (EOFException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("object truncated by") >= 0);
        }
    }

    private void testOverlongLengthRejected()
        throws Exception
    {
        // 9 length octets cannot fit a non-negative long
        byte[] hdr = new byte[]{ 0x04, (byte)0x89, 0x01, 0, 0, 0, 0, 0, 0, 0, 0 };
        ASN1StreamParser parser = new ASN1StreamParser(new ByteArrayInputStream(hdr));

        try
        {
            parser.readObject();
            fail("overlong length not rejected");
        }
        catch (IOException e)
        {
            isTrue(e.getMessage(), e.getMessage().indexOf("more than 63 bits") >= 0);
        }
    }

    /** TLV header: single-octet tag plus the definite-length octets for bodyLength. */
    private static byte[] header(int tag, long bodyLength)
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        bOut.write(tag);
        if (bodyLength < 0x80)
        {
            bOut.write((int)bodyLength);
        }
        else
        {
            int octets = 0;
            long l = bodyLength;
            while (l != 0)
            {
                octets++;
                l >>>= 8;
            }
            bOut.write(0x80 | octets);
            for (int i = (octets - 1) * 8; i >= 0; i -= 8)
            {
                bOut.write((int)(bodyLength >>> i));
            }
        }
        return bOut.toByteArray();
    }

    private static long drain(InputStream in)
        throws IOException
    {
        byte[] buf = new byte[1 << 16];
        long total = 0;
        int read;
        while ((read = in.read(buf)) >= 0)
        {
            if (buf[0] != FILL)
            {
                throw new IOException("unexpected content");
            }
            total += read;
        }
        return total;
    }

    /** Serves {@code count} octets of a fill value without holding them. */
    private static class FillStream
        extends InputStream
    {
        private long remaining;

        FillStream(long count)
        {
            remaining = count;
        }

        public int read()
        {
            if (remaining <= 0)
            {
                return -1;
            }
            remaining--;
            return FILL & 0xFF;
        }

        public int read(byte[] buf, int off, int len)
        {
            if (remaining <= 0)
            {
                return -1;
            }
            int n = (int)Math.min(len, remaining);
            java.util.Arrays.fill(buf, off, off + n, FILL);
            remaining -= n;
            return n;
        }
    }

    public static void main(String[] args)
    {
        runTest(new LongDefiniteLengthParserTest());
    }
}
