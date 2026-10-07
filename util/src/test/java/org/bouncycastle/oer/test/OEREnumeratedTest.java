package org.bouncycastle.oer.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.OEROutputStream;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * X.696 sec. 11.4 encodes an ENUMERATED value in the short form (one octet, bit 8 clear) only for
 * 0..127; every other value, negative ones included, takes the long form: a length octet with bit 8
 * set followed by the value as a two's-complement signed integer in the minimum number of octets.
 * The encoder used to pick the long form only for values above 127, so a negative value was
 * written in the short form masked to seven bits (-1 as 7F, the encoding of 127), and the decoder
 * read the long-form payload as unsigned (81 FF, the encoding of -1, as 255).
 */
public class OEREnumeratedTest
    extends TestCase
{
    private static final Element SCHEMA = OERDefinition.enumeration(
        OERDefinition.enumItem("negLong", BigInteger.valueOf(-129)),
        OERDefinition.enumItem("negByte", BigInteger.valueOf(-128)),
        OERDefinition.enumItem("minusOne", BigInteger.valueOf(-1)),
        OERDefinition.enumItem("zero", BigInteger.valueOf(0)),
        OERDefinition.enumItem("maxShort", BigInteger.valueOf(127)),
        OERDefinition.enumItem("minLong", BigInteger.valueOf(128)),
        OERDefinition.enumItem("big", BigInteger.valueOf(0x7FFFFFFFL))).build();

    /**
     * An enumerand's explicit value is what goes on the wire, not its index in the definition.
     * OERDefinition.Builder.enumValue() used to set the value on the builder it had just copied
     * from and return the copy, so every explicit value was dropped and the items were numbered
     * by position instead. With explicit values honoured, the automatic numbers follow X.680
     * sec. 20.3: the successive integers from 0, skipping any explicit root number.
     */
    public void testExplicitValuesHonoured()
        throws IOException
    {
        Element schema = OERDefinition.enumeration(
            OERDefinition.enumItem("ten", BigInteger.valueOf(10)),
            "auto",
            OERDefinition.enumItem("twenty", BigInteger.valueOf(20)),
            "zero-is-taken",
            OERDefinition.enumItem("one", BigInteger.valueOf(1)),
            OERDefinition.enumItem("minus", BigInteger.valueOf(-1))).build();

        assertEnumValues(schema, new long[]{ 10, 0, 20, 2, 1, -1 });

        assertEquals("0A", Hex.toHexString(encode(10, schema)).toUpperCase());
        assertEquals("00", Hex.toHexString(encode(0, schema)).toUpperCase());
        assertEquals("14", Hex.toHexString(encode(20, schema)).toUpperCase());
        assertEquals("81FF", Hex.toHexString(encode(-1, schema)).toUpperCase());

        // the positional values the dropped explicit values used to leave behind are not enumerands
        for (int notAnEnumerand = 3; notAnEnumerand <= 5; ++notAnEnumerand)
        {
            try
            {
                encode(notAnEnumerand, schema);
                fail(notAnEnumerand + " is not an enumerand");
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
        }
    }

    /** The four examples of X.680 sec. 20.6, plus one with every root number automatic. */
    public void testAdditionalEnumerationNumbering()
    {
        // A ::= ENUMERATED {a, b, ..., c}            -- c = 2
        assertEnumValues(OERDefinition.enumeration("a", "b", OERDefinition.extension("c")).build(),
            new long[]{ 0, 1, 2 });
        // B ::= ENUMERATED {a, b, c(0), ..., d}      -- d = 3
        assertEnumValues(OERDefinition.enumeration("a", "b", OERDefinition.enumItem("c", BigInteger.ZERO),
            OERDefinition.extension("d")).build(), new long[]{ 1, 2, 0, 3 });
        // C ::= ENUMERATED {a, b, ..., c(3), d}      -- d = 4
        assertEnumValues(OERDefinition.enumeration("a", "b",
            OERDefinition.extension(OERDefinition.enumItem("c", BigInteger.valueOf(3)), "d")).build(),
            new long[]{ 0, 1, 3, 4 });
        // D ::= ENUMERATED {a, z(25), ..., d}        -- d = 1
        assertEnumValues(OERDefinition.enumeration("a", OERDefinition.enumItem("z", BigInteger.valueOf(25)),
            OERDefinition.extension("d")).build(), new long[]{ 0, 25, 1 });

        // automatic numbers are non-negative (sec. 20.3), whatever the explicit ones around them are
        assertEnumValues(OERDefinition.enumeration(OERDefinition.enumItem("a", BigInteger.valueOf(-100)),
            OERDefinition.extension("b")).build(), new long[]{ -100, 0 });
        assertEnumValues(OERDefinition.enumeration("a",
            OERDefinition.extension(OERDefinition.enumItem("c", BigInteger.valueOf(-5)), "d")).build(),
            new long[]{ 0, -5, 1 });

        // an additional item skips every root number, automatic ones included
        assertEnumValues(OERDefinition.enumeration(OERDefinition.enumItem("ok", BigInteger.ZERO), "one", "two",
            OERDefinition.extension("three")).build(), new long[]{ 0, 1, 2, 3 });
    }

    /** The shipped ETSI TS 102 941 response codes give "ok" the value 0 at position 0, so their numbering is unchanged. */
    public void testEtsiResponseCodesUnchanged()
    {
        checkSequential(org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesEnrolment.EnrolmentResponseCode.build());
        checkSequential(org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesAuthorization.AuthorizationResponseCode.build());
        checkSequential(org.bouncycastle.oer.its.template.etsi102941.EtsiTs102941TypesAuthorizationValidation.AuthorizationValidationResponseCode.build());
    }

    private static void checkSequential(Element schema)
    {
        assertTrue(schema.getChildren().size() > 1);
        for (int i = 0; i < schema.getChildren().size(); ++i)
        {
            assertEquals(BigInteger.valueOf(i), ((Element)schema.getChildren().get(i)).getEnumValue());
        }
    }

    private static void assertEnumValues(Element schema, long[] expected)
    {
        assertEquals(expected.length, schema.getChildren().size());
        for (int i = 0; i < expected.length; ++i)
        {
            assertEquals("item " + i, BigInteger.valueOf(expected[i]), ((Element)schema.getChildren().get(i)).getEnumValue());
        }
    }

    public void testEncoding()
        throws IOException
    {
        checkEncoding(-129, "82FF7F");
        checkEncoding(-128, "8180");
        checkEncoding(-1, "81FF");
        checkEncoding(0, "00");
        checkEncoding(127, "7F");
        checkEncoding(128, "820080");
        checkEncoding(0x7FFFFFFF, "847FFFFFFF");
    }

    public void testDecoding()
        throws IOException
    {
        checkDecoding("82FF7F", -129);
        checkDecoding("8180", -128);
        checkDecoding("81FF", -1);
        checkDecoding("00", 0);
        checkDecoding("7F", 127);
        checkDecoding("820080", 128);
        checkDecoding("847FFFFFFF", 0x7FFFFFFF);
    }

    /** -1 must not collide with 127 on either side, as it used to. */
    public void testNegativeDistinctFromShortForm()
        throws IOException
    {
        assertFalse(Arrays.areEqual(encode(-1), encode(127)));
        assertEquals(-1, decode(encode(-1)).intValueExact());
        assertEquals(127, decode(encode(127)).intValueExact());
        assertEquals(-1, decode(Hex.decode("81FF")).intValueExact());
        assertEquals(255, decode(Hex.decode("8200FF")).intValueExact());
    }

    private static void checkEncoding(int value, String expectedHex)
        throws IOException
    {
        assertEquals("encoding of " + value, expectedHex, Hex.toHexString(encode(value)).toUpperCase());
    }

    private static void checkDecoding(String hex, int expected)
        throws IOException
    {
        ASN1Enumerated decoded = decode(Hex.decode(hex));
        assertEquals("decoding of " + hex, expected, decoded.intValueExact());
        assertEquals("negative flag for " + hex, expected < 0, decoded.isNegative());
    }

    private static byte[] encode(int value)
        throws IOException
    {
        return encode(value, SCHEMA);
    }

    private static byte[] encode(int value, Element schema)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OEROutputStream oerOut = new OEROutputStream(bOut);
        oerOut.write(ASN1Enumerated.valueOf(value), schema);
        oerOut.flush();
        return bOut.toByteArray();
    }

    private static ASN1Enumerated decode(byte[] encoding)
        throws IOException
    {
        return ASN1Enumerated.getInstance(OERInputStream.parse(encoding, SCHEMA));
    }
}
