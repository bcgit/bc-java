package org.bouncycastle.oer.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.OEROutputStream;
import org.bouncycastle.util.encoders.Hex;

/**
 * X.696 sec. 10: an INTEGER whose effective value constraint has a lower bound of zero or more
 * (10.2 a) takes a fixed-size unsigned word of 1, 2, 4 or 8 octets when the upper bound fits
 * (10.3 a-d), otherwise a length determinant and a variable-size unsigned number (10.3 e); one
 * with a negative lower bound or none (10.2 b) takes a fixed-size signed word when both bounds fit
 * (10.4 a-d), otherwise a length determinant and a variable-size signed number (10.4 e).
 */
public class OERIntegerTest
    extends TestCase
{
    private static final BigInteger TWO_64 = BigInteger.ONE.shiftLeft(64);
    private static final BigInteger TWO_63 = BigInteger.ONE.shiftLeft(63);

    /** 10.3 a-d: a lower bound of 0 and an upper bound at each unsigned word's maximum. */
    public void testUnsignedFixedSize()
        throws IOException
    {
        check(range(0, 255), 0, "00");
        check(range(0, 255), 255, "FF");
        check(range(0, 256), 256, "0100");
        check(range(0, 65535), 65535, "FFFF");
        check(range(0, 65536), 65536, "00010000");
        check(range(0, 4294967295L), 4294967295L, "FFFFFFFF");
        check(range(0, 4294967296L), 4294967296L, "0000000100000000");
        check(range(BigInteger.ZERO, TWO_64.subtract(BigInteger.ONE)), TWO_64.subtract(BigInteger.ONE), "FFFFFFFFFFFFFFFF");
    }

    /**
     * 10.2 a) says "zero or positive", so a positive lower bound takes the unsigned forms too. The
     * decoder and encoder used to test for a lower bound of exactly zero, so INTEGER (1..255) was
     * a two-octet signed word and INTEGER (1..MAX) a variable-size signed number.
     */
    public void testPositiveLowerBoundIsUnsigned()
        throws IOException
    {
        check(range(1, 255), 1, "01");
        check(range(1, 255), 255, "FF");
        check(range(5, 300), 300, "012C");
        check(range(1000, 70000), 70000, "00011170");

        // 10.3 e) with a positive lower bound: unsigned, so 128 is one octet, not 00 80
        Element oneToMax = OERDefinition.integer().rangeToMAXFrom(1).build();
        check(oneToMax, 1, "0101");
        check(oneToMax, 128, "0180");
        check(oneToMax, 65536, "03010000");
    }

    /** 10.3 e): a lower bound of 0 with no upper bound, or one past 2^64 - 1. */
    public void testUnsignedVariableSize()
        throws IOException
    {
        Element zeroToMax = OERDefinition.integer().rangeToMAXFrom(0).build();
        check(zeroToMax, 0, "0100");
        check(zeroToMax, 127, "017F");
        check(zeroToMax, 128, "0180");
        check(zeroToMax, 256, "020100");
        check(zeroToMax, TWO_64, "09010000000000000000");

        Element pastEightOctets = OERDefinition.integer(BigInteger.ZERO, TWO_64).build();
        check(pastEightOctets, 0, "0100");
        check(pastEightOctets, TWO_64, "09010000000000000000");
    }

    /** 10.4 e): no bounds, or bounds outside the eight-octet signed word, are a variable-size signed number. */
    public void testSignedVariableSize()
        throws IOException
    {
        Element unbounded = OERDefinition.integer().build();
        check(unbounded, 0, "0100");
        check(unbounded, 127, "017F");
        check(unbounded, 128, "020080");
        check(unbounded, -1, "01FF");
        check(unbounded, -128, "0180");
        check(unbounded, -129, "02FF7F");

        Element belowEightOctets = OERDefinition.integer(TWO_63.negate().subtract(BigInteger.ONE), BigInteger.ZERO).build();
        check(belowEightOctets, -1, "01FF");
        check(belowEightOctets, TWO_63.negate().subtract(BigInteger.ONE), "09FF7FFFFFFFFFFFFFFF");

        // a negative lower bound with no upper bound
        Element minusOneToMax = OERDefinition.integer().rangeToMAXFrom(-1).build();
        check(minusOneToMax, -1, "01FF");
        check(minusOneToMax, 128, "020080");
    }

    /**
     * 10.4 a-d): both bounds are inclusive. The upper-bound comparison used to be strict, so a range
     * ending exactly at the word's maximum (-128..127, -32768..32767, ...) took the next word up.
     */
    public void testSignedFixedSize()
        throws IOException
    {
        check(range(-128, 127), -128, "80");
        check(range(-128, 127), 127, "7F");
        check(range(-128, 128), 128, "0080");
        check(range(-129, 127), -129, "FF7F");
        check(range(-32768, 32767), 32767, "7FFF");
        check(range(-32768, 32768), 32768, "00008000");
        check(range(-2147483648L, 2147483647L), 2147483647L, "7FFFFFFF");
        check(range(-2147483648L, 2147483648L), 2147483648L, "0000000080000000");
        check(range(TWO_63.negate(), TWO_63.subtract(BigInteger.ONE)), TWO_63.subtract(BigInteger.ONE), "7FFFFFFFFFFFFFFF");
        check(range(TWO_63.negate(), TWO_63.subtract(BigInteger.ONE)), TWO_63.negate(), "8000000000000000");

        // a one-sided negative range: upper bound inside the one-octet word, lower bound not
        check(range(-200, 0), -200, "FF38");
        check(range(-1, 1), -1, "FF");
        check(range(-1, 1), 1, "01");
    }

    private static Element range(long lower, long upper)
    {
        return OERDefinition.integer(lower, upper).build();
    }

    private static Element range(BigInteger lower, BigInteger upper)
    {
        return OERDefinition.integer(lower, upper).build();
    }

    private static void check(Element schema, long value, String expectedHex)
        throws IOException
    {
        check(schema, BigInteger.valueOf(value), expectedHex);
    }

    private static void check(Element schema, BigInteger value, String expectedHex)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OEROutputStream oerOut = new OEROutputStream(bOut);
        oerOut.write(new ASN1Integer(value), schema);
        oerOut.flush();
        byte[] encoding = bOut.toByteArray();

        assertEquals("encoding of " + value + " under " + schema.rangeExpression(), expectedHex,
            Hex.toHexString(encoding).toUpperCase());

        ASN1Integer decoded = ASN1Integer.getInstance(OERInputStream.parse(encoding, schema));
        assertEquals("decoding of " + expectedHex + " under " + schema.rangeExpression(), value, decoded.getValue());
    }
}
