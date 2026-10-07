package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.math.BigInteger;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Hex;

/**
 * Tests used to verify correct decoding of the ENUMERATED type.
 */
public class EnumeratedTest
    extends TestCase
{
    /**
     * Test vector used to test decoding of multiple items. This sample uses an ENUMERATED and a BOOLEAN.
     */
    private static final byte[] MultipleSingleByteItems = Hex.decode("30060a01010101ff");

    /**
     * Test vector used to test decoding of multiple items. This sample uses two ENUMERATEDs.
     */
    private static final byte[] MultipleDoubleByteItems = Hex.decode("30080a0201010a020202");

    /**
     * Test vector used to test decoding of multiple items. This sample uses an ENUMERATED and an OBJECT IDENTIFIER.
     */
    private static final byte[] MultipleTripleByteItems = Hex.decode("300a0a0301010106032b0601");

    /**
     * Makes sure multiple identically sized values are parsed correctly.
     */
    public void testReadingMultipleSingleByteItems()
        throws IOException
    {
        ASN1Primitive obj = ASN1Primitive.fromByteArray(MultipleSingleByteItems);

        assertTrue("Null ASN.1 SEQUENCE", obj instanceof ASN1Sequence);

        ASN1Sequence sequence = (ASN1Sequence)obj;

        assertEquals("2 items expected", 2, sequence.size());

        ASN1Enumerated enumerated = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

        assertNotNull("ENUMERATED expected", enumerated);

        assertEquals("Unexpected ENUMERATED value", 1, enumerated.intValueExact());
        assertTrue("Unexpected ENUMERATED value", enumerated.hasValue(1));

        ASN1Boolean b = ASN1Boolean.getInstance(sequence.getObjectAt(1));

        assertNotNull("BOOLEAN expected", b);

        assertTrue("Unexpected BOOLEAN value", b.isTrue());
    }

    /**
     * Makes sure multiple identically sized values are parsed correctly.
     */
    public void testReadingMultipleDoubleByteItems()
        throws IOException
    {
        ASN1Primitive obj = ASN1Primitive.fromByteArray(MultipleDoubleByteItems);

        assertTrue("Null ASN.1 SEQUENCE", obj instanceof ASN1Sequence);

        ASN1Sequence sequence = (ASN1Sequence)obj;

        assertEquals("2 items expected", 2, sequence.size());

        ASN1Enumerated enumerated1 = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

        assertNotNull("ENUMERATED expected", enumerated1);

        assertEquals("Unexpected ENUMERATED value", 257, enumerated1.intValueExact());
        assertTrue("Unexpected ENUMERATED value", enumerated1.hasValue(257));

        ASN1Enumerated enumerated2 = ASN1Enumerated.getInstance(sequence.getObjectAt(1));

        assertNotNull("ENUMERATED expected", enumerated2);

        assertEquals("Unexpected ENUMERATED value", 514, enumerated2.intValueExact());
        assertTrue("Unexpected ENUMERATED value", enumerated2.hasValue(514));
    }

    /**
     * Makes sure multiple identically sized values are parsed correctly.
     */
    public void testReadingMultipleTripleByteItems()
        throws IOException
    {
        ASN1Primitive obj = ASN1Primitive.fromByteArray(MultipleTripleByteItems);

        assertTrue("Null ASN.1 SEQUENCE", obj instanceof ASN1Sequence);

        ASN1Sequence sequence = (ASN1Sequence)obj;

        assertEquals("2 items expected", 2, sequence.size());

        ASN1Enumerated enumerated = ASN1Enumerated.getInstance(sequence.getObjectAt(0));

        assertNotNull("ENUMERATED expected", enumerated);

        assertEquals("Unexpected ENUMERATED value", 65793, enumerated.intValueExact());
        assertTrue("Unexpected ENUMERATED value", enumerated.hasValue(65793));

        ASN1ObjectIdentifier objectId = ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(1));

        assertNotNull("OBJECT IDENTIFIER expected", objectId);

        assertEquals("Unexpected OBJECT IDENTIFIER value", "1.3.6.1", objectId.getId());
    }

    /**
     * ENUMERATED values are integers (X.680 sec. 20) and may be negative.
     */
    public void testNegativeValues()
        throws IOException
    {
        checkNegative(new ASN1Enumerated(-1), -1);
        checkNegative(new ASN1Enumerated(BigInteger.valueOf(-1)), -1);
        checkNegative(new ASN1Enumerated(new byte[]{ (byte)0xFF }), -1);
        checkNegative(new ASN1Enumerated(-129), -129);
        checkNegative(new ASN1Enumerated(Integer.MIN_VALUE), Integer.MIN_VALUE);

        ASN1Enumerated beyondInt = new ASN1Enumerated(BigInteger.valueOf(Long.MIN_VALUE));
        assertTrue(beyondInt.isNegative());
        assertEquals(Long.MIN_VALUE, beyondInt.longValueExact());
        try
        {
            beyondInt.intValueExact();
            fail("int range");
        }
        catch (ArithmeticException e)
        {
            // expected
        }

        assertFalse(new ASN1Enumerated(0).isNegative());
        assertFalse(new ASN1Enumerated(255).isNegative());
        assertEquals(255L, new ASN1Enumerated(255).longValueExact());
    }

    private void checkNegative(ASN1Enumerated enumerated, int value)
        throws IOException
    {
        assertTrue(enumerated.isNegative());
        assertTrue(enumerated.hasValue(value));
        assertTrue(enumerated.hasValue(BigInteger.valueOf(value)));
        assertEquals(value, enumerated.intValueExact());
        assertEquals((long)value, enumerated.longValueExact());
        assertEquals(BigInteger.valueOf(value), enumerated.getValue());

        byte[] encoding = enumerated.getEncoded();
        assertEquals(BigInteger.valueOf(value).toByteArray().length + 2, encoding.length);

        ASN1Enumerated decoded = ASN1Enumerated.getInstance(ASN1Primitive.fromByteArray(encoding));
        assertEquals(enumerated, decoded);
        assertEquals(enumerated.hashCode(), decoded.hashCode());
        assertTrue(decoded.isNegative());
        assertEquals(value, decoded.intValueExact());

        decoded = ASN1Enumerated.getInstance(encoding);
        assertEquals(enumerated, decoded);
        assertEquals(value, decoded.intValueExact());
    }
}
