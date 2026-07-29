package org.bouncycastle.cbor.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.cbor.CBORDecoder;
import org.bouncycastle.cbor.CBOREncoder;
import org.bouncycastle.cbor.CBORType;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tests for the deterministic CBOR reader/writer, driven by the worked examples in
 * RFC 8949 Appendix A plus negative tests for each of the deterministic encoding
 * requirements of RFC 8949 Section 4.2.1.
 */
public class CBORCodecTest
    extends TestCase
{
    public void testUnsignedIntegerVectors()
        throws Exception
    {
        // RFC 8949 Appendix A
        checkUnsigned(0L, "00");
        checkUnsigned(1L, "01");
        checkUnsigned(10L, "0a");
        checkUnsigned(23L, "17");
        checkUnsigned(24L, "1818");
        checkUnsigned(25L, "1819");
        checkUnsigned(100L, "1864");
        checkUnsigned(1000L, "1903e8");
        checkUnsigned(1000000L, "1a000f4240");
        checkUnsigned(1000000000000L, "1b000000e8d4a51000");
    }

    public void testNegativeIntegerVectors()
        throws Exception
    {
        checkInteger(-1L, "20");
        checkInteger(-10L, "29");
        checkInteger(-100L, "3863");
        checkInteger(-1000L, "3903e7");
    }

    public void testBigIntegerRange()
        throws Exception
    {
        // 18446744073709551615 (2^64 - 1)
        checkBigInteger(new BigInteger("18446744073709551615"), "1bffffffffffffffff");
        // -18446744073709551616 (-2^64)
        checkBigInteger(new BigInteger("-18446744073709551616"), "3bffffffffffffffff");
        checkBigInteger(BigInteger.valueOf(500), "1901f4");
        checkBigInteger(BigInteger.valueOf(-500), "3901f3");

        // values outside -2^64 .. 2^64-1 must be rejected by the encoder
        try
        {
            encodeBigInteger(new BigInteger("18446744073709551616"));
            fail("out of range biginteger accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
        try
        {
            encodeBigInteger(new BigInteger("-18446744073709551617"));
            fail("out of range biginteger accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        // 2^64-1 does not fit the long-returning accessors
        try
        {
            new CBORDecoder(Hex.decode("1bffffffffffffffff")).readUnsignedInteger();
            fail("uint64 out of long range accepted");
        }
        catch (IOException e)
        {
            // expected
        }
        try
        {
            new CBORDecoder(Hex.decode("3bffffffffffffffff")).readInteger();
            fail("nint64 out of long range accepted");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    public void testStringVectors()
        throws Exception
    {
        checkByteString(new byte[0], "40");
        checkByteString(Hex.decode("01020304"), "4401020304");
        checkTextString("", "60");
        checkTextString("a", "6161");
        checkTextString("IETF", "6449455446");
        checkTextString("\"\\", "62225c");
        checkTextString("ü", "62c3bc");
        checkTextString("水", "63e6b0b4");
    }

    public void testArrayAndTagVectors()
        throws Exception
    {
        // []
        CBORDecoder dec = new CBORDecoder(Hex.decode("80"));
        assertEquals(0, dec.readArrayHeader());
        dec.expectEnd();

        // [1, 2, 3]
        dec = new CBORDecoder(Hex.decode("83010203"));
        assertEquals(3, dec.readArrayHeader());
        assertEquals(1, dec.readInt());
        assertEquals(2, dec.readInt());
        assertEquals(3, dec.readInt());
        dec.expectEnd();

        // [1, [2, 3], [4, 5]]
        dec = new CBORDecoder(Hex.decode("8301820203820405"));
        assertEquals(3, dec.readArrayHeader());
        assertEquals(1, dec.readInt());
        assertEquals(2, dec.readArrayHeader());
        assertEquals(2, dec.readInt());
        assertEquals(3, dec.readInt());
        assertTrue(Arrays.areEqual(Hex.decode("820405"), dec.readEncodedItem()));
        dec.expectEnd();

        // 1(1363896240)
        dec = new CBORDecoder(Hex.decode("c11a514b67b0"));
        assertEquals(CBORType.TAG, dec.peekMajorType());
        assertEquals(1L, dec.readTag());
        assertEquals(1363896240L, dec.readUnsignedInteger());
        dec.expectEnd();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder enc = new CBOREncoder(bOut);
        enc.writeTag(1);
        enc.writeUnsignedInteger(1363896240L);
        assertTrue(Arrays.areEqual(Hex.decode("c11a514b67b0"), bOut.toByteArray()));
    }

    public void testSimpleValues()
        throws Exception
    {
        CBORDecoder dec = new CBORDecoder(Hex.decode("f4"));
        assertFalse(dec.readBoolean());
        dec = new CBORDecoder(Hex.decode("f5"));
        assertTrue(dec.readBoolean());
        dec = new CBORDecoder(Hex.decode("f6"));
        assertTrue(dec.nextIsNull());
        dec.readNull();
        dec = new CBORDecoder(Hex.decode("f7"));
        assertTrue(dec.nextIsUndefined());
        dec.readUndefined();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        CBOREncoder enc = new CBOREncoder(bOut);
        enc.writeBoolean(false);
        enc.writeBoolean(true);
        enc.writeNull();
        enc.writeUndefined();
        assertTrue(Arrays.areEqual(Hex.decode("f4f5f6f7"), bOut.toByteArray()));
    }

    public void testMapValidationInEncodedItem()
        throws Exception
    {
        // {1: 2, 3: 4} - sorted keys accepted
        CBORDecoder dec = new CBORDecoder(Hex.decode("a201020304"));
        assertTrue(Arrays.areEqual(Hex.decode("a201020304"), dec.readEncodedItem()));
        dec.expectEnd();

        // {3: 4, 1: 2} - unsorted keys rejected
        expectMalformed("a203040102", "unsorted map keys");
        // {1: 2, 1: 4} - duplicate keys rejected
        expectMalformed("a201020104", "duplicate map keys");
    }

    public void testRejectsNonShortestForms()
        throws Exception
    {
        expectMalformed("1800", "argument 0 in 1+1 form");
        expectMalformed("1817", "argument 23 in 1+1 form");
        expectMalformed("1900ff", "argument 255 in 1+2 form");
        expectMalformed("1a0000ffff", "argument 65535 in 1+4 form");
        expectMalformed("1b00000000ffffffff", "argument in 1+8 form below 2^32");
        expectMalformed("5820" + repeat("00", 31), "byte string length exceeding remaining data");
    }

    public void testRejectsIndefiniteLengths()
        throws Exception
    {
        expectMalformed("5f42010243030405ff", "indefinite-length byte string");
        expectMalformed("7f657374726561646d696e67ff", "indefinite-length text string");
        expectMalformed("9f018202039f0405ffff", "indefinite-length array");
        expectMalformed("bf61610161629f0203ffff", "indefinite-length map");
    }

    public void testRejectsFloatsAndUnsupportedSimples()
        throws Exception
    {
        expectMalformed("f90000", "half-precision float");
        expectMalformed("fa47c35000", "single-precision float");
        expectMalformed("fb7e37e43c8800759c", "double-precision float");
        expectMalformed("f0", "simple value 16");
        expectMalformed("f818", "two-byte simple value");
        expectMalformed("f8ff", "two-byte simple value 255");
    }

    public void testRejectsMalformedStructure()
        throws Exception
    {
        expectMalformed("", "empty input");
        expectMalformed("18", "truncated argument");
        expectMalformed("1c", "reserved additional information 28");
        expectMalformed("1d", "reserved additional information 29");
        expectMalformed("1e", "reserved additional information 30");
        expectMalformed("43ffff", "byte string truncated");
        expectMalformed("62c328", "text string with invalid UTF-8");
        expectMalformed("6dfffe6465746563742055544632", "text string with invalid UTF-8 start");
        expectMalformed("81", "array with missing element");
        expectMalformed("9b0020000000000000", "array count exceeding remaining data");
        expectMalformed("a1", "map with missing entry");
        expectMalformed("c1", "tag with missing content");
    }

    public void testNestingDepthBounded()
        throws Exception
    {
        // 100 nested single-element arrays overflow the decoder's depth bound; the
        // failure must be a clean IOException, not a StackOverflowError.
        StringBuffer deep = new StringBuffer();
        for (int i = 0; i != 100; i++)
        {
            deep.append("81");
        }
        deep.append("00");
        expectMalformed(deep.toString(), "excessive nesting");
    }

    public void testEncodedItemRoundTrips()
        throws Exception
    {
        String[] items = new String[]
        {
            "00", "17", "1818", "1903e8", "20", "3863", "40", "4401020304", "60",
            "6449455446", "80", "83010203", "8301820203820405", "a201020304",
            "c249010000000000000000", "d818456449455446", "f4", "f5", "f6", "f7"
        };
        for (int i = 0; i != items.length; i++)
        {
            byte[] encoding = Hex.decode(items[i]);
            CBORDecoder dec = new CBORDecoder(encoding);
            byte[] item = dec.readEncodedItem();
            dec.expectEnd();
            assertTrue(items[i], Arrays.areEqual(encoding, item));

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            new CBOREncoder(bOut).writeEncoded(item);
            assertTrue(items[i], Arrays.areEqual(encoding, bOut.toByteArray()));
        }
    }

    public void testEncoderBoundaryValues()
        throws Exception
    {
        checkEncodeInteger(0L, "00");
        checkEncodeInteger(23L, "17");
        checkEncodeInteger(24L, "1818");
        checkEncodeInteger(255L, "18ff");
        checkEncodeInteger(256L, "190100");
        checkEncodeInteger(65535L, "19ffff");
        checkEncodeInteger(65536L, "1a00010000");
        checkEncodeInteger(4294967295L, "1affffffff");
        checkEncodeInteger(4294967296L, "1b0000000100000000");
        checkEncodeInteger(Long.MAX_VALUE, "1b7fffffffffffffff");
        checkEncodeInteger(-1L, "20");
        checkEncodeInteger(-24L, "37");
        checkEncodeInteger(-25L, "3818");
        checkEncodeInteger(-256L, "38ff");
        checkEncodeInteger(-257L, "390100");
        checkEncodeInteger(Long.MIN_VALUE, "3b7fffffffffffffff");
    }

    public void testSliceConstructor()
        throws Exception
    {
        byte[] padded = Hex.decode("ff0102ff");
        CBORDecoder dec = new CBORDecoder(padded, 1, 2);
        assertEquals(1, dec.readInt());
        assertEquals(2, dec.readInt());
        dec.expectEnd();

        try
        {
            new CBORDecoder(padded, 3, 2);
            fail("invalid slice accepted");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private String repeat(String s, int count)
    {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i != count; i++)
        {
            sb.append(s);
        }
        return sb.toString();
    }

    private void expectMalformed(String hexEncoding, String description)
    {
        byte[] encoding = Hex.decode(hexEncoding);
        try
        {
            CBORDecoder dec = new CBORDecoder(encoding);
            dec.readEncodedItem();
            dec.expectEnd();
            fail("accepted " + description);
        }
        catch (IOException e)
        {
            // expected - and only IOException is acceptable at a decode boundary
        }
    }

    private void checkUnsigned(long value, String hexEncoding)
        throws IOException
    {
        CBORDecoder dec = new CBORDecoder(Hex.decode(hexEncoding));
        assertEquals(CBORType.UNSIGNED_INTEGER, dec.peekMajorType());
        assertEquals(value, dec.readUnsignedInteger());
        dec.expectEnd();
        checkEncodeInteger(value, hexEncoding);
    }

    private void checkInteger(long value, String hexEncoding)
        throws IOException
    {
        CBORDecoder dec = new CBORDecoder(Hex.decode(hexEncoding));
        assertEquals(value, dec.readInteger());
        dec.expectEnd();
        checkEncodeInteger(value, hexEncoding);
    }

    private void checkBigInteger(BigInteger value, String hexEncoding)
        throws IOException
    {
        CBORDecoder dec = new CBORDecoder(Hex.decode(hexEncoding));
        assertEquals(value, dec.readBigInteger());
        dec.expectEnd();
        assertTrue(Arrays.areEqual(Hex.decode(hexEncoding), encodeBigInteger(value)));
    }

    private byte[] encodeBigInteger(BigInteger value)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeInteger(value);
        return bOut.toByteArray();
    }

    private void checkEncodeInteger(long value, String hexEncoding)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeInteger(value);
        assertTrue(Arrays.areEqual(Hex.decode(hexEncoding), bOut.toByteArray()));
    }

    private void checkByteString(byte[] value, String hexEncoding)
        throws IOException
    {
        CBORDecoder dec = new CBORDecoder(Hex.decode(hexEncoding));
        assertTrue(Arrays.areEqual(value, dec.readByteString()));
        dec.expectEnd();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeByteString(value);
        assertTrue(Arrays.areEqual(Hex.decode(hexEncoding), bOut.toByteArray()));
    }

    private void checkTextString(String value, String hexEncoding)
        throws IOException
    {
        CBORDecoder dec = new CBORDecoder(Hex.decode(hexEncoding));
        assertEquals(value, dec.readTextString());
        dec.expectEnd();

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        new CBOREncoder(bOut).writeTextString(value);
        assertTrue(Arrays.areEqual(Hex.decode(hexEncoding), bOut.toByteArray()));
    }
}
