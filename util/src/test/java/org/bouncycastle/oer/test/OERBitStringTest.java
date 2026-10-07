package org.bouncycastle.oer.test;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.OEROutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * X.696 clause 13: a BIT STRING whose size constraint is a single value is encoded as its octets
 * alone (13.2); any other BIT STRING takes a length determinant covering an initial octet, which
 * gives the number of unused bits in the final octet, and the octets of the value (13.3). The
 * decoder's variable-size path used to read the determinant as a bit count, divide it by 8 and
 * never read the initial octet, so it could not decode what the encoder wrote.
 */
public class OERBitStringTest
    extends TestCase
{
    public void testFixedSize()
        throws IOException
    {
        check(OERDefinition.bitString(8).build(), new DERBitString(Hex.decode("A5")), "A5");
        check(OERDefinition.bitString(16).build(), new DERBitString(Hex.decode("A55A")), "A55A");
        // a size that is not a whole number of octets: 13.2.2, the unused bits of the final octet
        check(OERDefinition.bitString(12).build(), new DERBitString(Hex.decode("ABC0"), 4), "ABC0");
        check(OERDefinition.bitString(1).build(), new DERBitString(Hex.decode("80"), 7), "80");
    }

    public void testVariableSize()
        throws IOException
    {
        Element unbounded = OERDefinition.bitString().build();
        check(unbounded, new DERBitString(new byte[0]), "0100");                   // 13.3.4
        check(unbounded, new DERBitString(Hex.decode("A5")), "0200A5");
        check(unbounded, new DERBitString(Hex.decode("ABC0"), 4), "0304ABC0");
        check(unbounded, new DERBitString(Hex.decode("80"), 7), "020780");

        // a size range is not fixed, so it takes the same form (13.1)
        Element ranged = OERDefinition.bitString(8, 64).build();
        check(ranged, new DERBitString(Hex.decode("A5")), "0200A5");
        check(ranged, new DERBitString(Hex.decode("A55AA55AA55AA55A")), "0900A55AA55AA55AA55A");
    }

    public void testMalformedVariableSizeRejected()
    {
        Element unbounded = OERDefinition.bitString().build();
        assertRejected("no initial octet", unbounded, Hex.decode("00"));
        assertRejected("8 unused bits", unbounded, Hex.decode("0208A5"));
        assertRejected("empty with unused bits", unbounded, Hex.decode("0104"));
        assertTruncated("missing initial octet", unbounded, Hex.decode("01"));
        assertTruncated("short data", unbounded, Hex.decode("0300A5"));
        assertTruncated("short fixed", OERDefinition.bitString(16).build(), Hex.decode("A5"));
    }

    private static void check(Element schema, ASN1BitString value, String expectedHex)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OEROutputStream oerOut = new OEROutputStream(bOut);
        oerOut.write(value, schema);
        oerOut.flush();
        byte[] encoding = bOut.toByteArray();
        assertEquals(schema.rangeExpression(), expectedHex, Hex.toHexString(encoding).toUpperCase());

        ASN1BitString decoded = ASN1BitString.getInstance(OERInputStream.parse(encoding, schema));
        assertTrue(schema.rangeExpression() + " bytes", Arrays.areEqual(value.getBytes(), decoded.getBytes()));
        assertEquals(schema.rangeExpression() + " unused bits", value.getPadBits(), decoded.getPadBits());
        assertEquals(schema.rangeExpression() + " value", value, decoded);
    }

    private static void assertRejected(String what, Element schema, byte[] encoding)
    {
        try
        {
            OERInputStream.parse(encoding, schema);
            fail(what + ": accepted");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    private static void assertTruncated(String what, Element schema, byte[] encoding)
    {
        try
        {
            OERInputStream.parse(encoding, schema);
            fail(what + ": accepted");
        }
        catch (EOFException e)
        {
            // expected
        }
        catch (IOException e)
        {
            fail(what + ": rejected as " + e);
        }
    }
}
