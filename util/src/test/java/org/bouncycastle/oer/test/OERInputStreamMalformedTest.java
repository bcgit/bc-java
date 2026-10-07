package org.bouncycastle.oer.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;

/**
 * OERInputStream.parse declares only IOException, and its callers in pkix - ETSISignedData(byte[]),
 * ETSIEncryptedData(byte[]) - propagate only that. Several fields taken straight from the encoding
 * used to index schema-sized structures or convert to int without a range check, so a couple of
 * malformed bytes raised an unchecked RuntimeException past that contract, before any signature
 * check: an out-of-range or overflowing CHOICE tag, an unimplemented CHOICE tag class, a length
 * determinant too large for an int, an absent or over-large unused-bit count in an extension
 * presence bitmap, and an out-of-range ENUM value whose schema label lookup was being built eagerly
 * for a debug message that was not being printed. X.696 sec. 8.7 makes an unknown CHOICE
 * alternative a decode error, which is what the rest of the BC codecs report as IOException.
 */
public class OERInputStreamMalformedTest
    extends TestCase
{
    private static Element choiceOfTwo()
    {
        return OERDefinition.choice(OERDefinition.bool(), OERDefinition.bool()).build();
    }

    private static Element seqWithExtension()
    {
        return OERDefinition.seq(OERDefinition.bool(), OERDefinition.extension()).build();
    }

    private void assertRejected(String label, Element schema, byte[] payload)
    {
        try
        {
            OERInputStream.parse(payload, schema);
            fail(label + ": accepted");
        }
        catch (IOException e)
        {
            // expected - the point is that nothing unchecked escapes
        }
        catch (RuntimeException e)
        {
            fail(label + ": unchecked " + e.getClass().getName() + ": " + e.getMessage());
        }
    }

    public void testChoiceTagBeyondAlternatives()
    {
        // context-specific, tag 63 so the tag continues, then continuation octets encoding 128
        assertRejected("tag 128 of 2", choiceOfTwo(), new byte[]{(byte)0xBF, (byte)0x81, 0x00, 0x00});
    }

    public void testChoiceTagContinuationOverflow()
    {
        // the continuation ends only on a clear bit 7, so the accumulating shift could go negative
        assertRejected("overflowing tag", choiceOfTwo(),
            new byte[]{(byte)0xBF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x7F, 0x00});

        byte[] many = new byte[4002];
        many[0] = (byte)0xBF;
        for (int i = 1; i != 4001; ++i)
        {
            many[i] = (byte)0xFF;
        }
        assertRejected("4000 continuation octets", choiceOfTwo(), many);
    }

    public void testChoiceUnimplementedTagClasses()
    {
        // the tag class is two bits off the wire; none of these three is a decoder state error
        assertRejected("universal", choiceOfTwo(), new byte[]{0x00, 0x00});
        assertRejected("application", choiceOfTwo(), new byte[]{0x40, 0x00});
        assertRejected("private", choiceOfTwo(), new byte[]{(byte)0xC0, 0x00});
    }

    public void testLengthDeterminantTooLargeForInt()
    {
        assertRejected("octets, 5-octet length", OERDefinition.octets().build(),
            new byte[]{(byte)0x85, 0x01, 0x02, 0x03, 0x04, 0x05});
        assertRejected("utf8, 8-octet length", OERDefinition.utf8String().build(),
            new byte[]{(byte)0x88, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                (byte)0xFF, (byte)0xFF, (byte)0xFF});
        assertRejected("ia5, 6-octet length", OERDefinition.ia5String().build(),
            new byte[]{(byte)0x86, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06});
        assertRejected("seqof, 5-octet count", OERDefinition.seqof(OERDefinition.bool()).build(),
            new byte[]{(byte)0x85, 0x01, 0x02, 0x03, 0x04, 0x05});
    }

    public void testExtensionPresenceBitmapMalformed()
    {
        // no unused-bit count octet at all
        assertRejected("zero-length presence list", seqWithExtension(),
            new byte[]{(byte)0x80, 0x00, 0x00});

        // a count of 0x80..0xFF sign-extended negative, making the bitmap's end overshoot
        assertRejected("presence list pad 0xFF", seqWithExtension(),
            new byte[]{(byte)0x80, 0x00, 0x01, (byte)0xFF});

        // and a count that is simply not a number of unused bits in an octet
        assertRejected("presence list pad 8", seqWithExtension(),
            new byte[]{(byte)0x80, 0x00, 0x02, 0x08, (byte)0x80});
    }

    /**
     * An ENUM value the schema has no enumerand for must not throw: the decode never validated the
     * value against the schema (it returns the ASN1Enumerated as read, and enumerands may carry
     * explicit values that are not child indices), so the only reason it used to fail was the
     * eagerly-built debug string. Tightening it into a rejection would change what the decoder
     * accepts, so the value still comes back as it did.
     */
    public void testEnumValueOutOfRangeStillDecodes()
        throws IOException
    {
        Element schema = OERDefinition.enumeration(
            OERDefinition.enumItem("a"), OERDefinition.enumItem("b")).build();

        // long-form ENUM value 0x7FFFFFFF, far past the two enumerands
        assertNotNull(OERInputStream.parse(
            new byte[]{(byte)0x84, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF}, schema));
    }

    /**
     * A truncated stream must fail, not decode what did arrive. The two length-prefixed INTEGER
     * branches and the BIT STRING branch read with Streams.readFully and ignored its (best-effort)
     * return, so a determinant of 4 followed by 2 bytes and end of stream decoded the zero-padded
     * buffer as a value. Every read now goes through Streams.readLenBytesFully, which throws
     * EOFException at the real end of input.
     */
    public void testTruncatedInputRejected()
    {
        Element unsigned = OERDefinition.integer().rangeToMAXFrom(0).build();
        Element signed = OERDefinition.integer().build();
        Element uint32 = OERDefinition.integer(0, 4294967295L).build();
        Element bits = OERDefinition.bitString(16).build();
        Element octets = OERDefinition.octets().build();

        assertTruncated("unsigned INTEGER", unsigned, new byte[]{0x04, 0x01, 0x02});
        assertTruncated("signed INTEGER", signed, new byte[]{0x04, 0x01, 0x02});
        assertTruncated("fixed-width INTEGER", uint32, new byte[]{0x01, 0x02, 0x03});
        assertTruncated("BIT STRING", bits, new byte[]{0x01});
        assertTruncated("OCTET STRING", octets, new byte[]{0x04, 0x01, 0x02});

        // a long-form length within the allocation cap but with nothing behind it
        assertTruncated("large unsigned INTEGER", unsigned, new byte[]{(byte)0x83, 0x0F, 0x00, 0x00, 0x01});
        assertTruncated("large OCTET STRING", octets, new byte[]{(byte)0x83, 0x0F, 0x00, 0x00, 0x01});
    }

    private static void assertTruncated(String what, Element schema, byte[] encoding)
    {
        try
        {
            OERInputStream.parse(encoding, schema);
            fail(what + ": truncated input accepted");
        }
        catch (java.io.EOFException e)
        {
            // expected
        }
        catch (IOException e)
        {
            fail(what + ": truncated input rejected as " + e);
        }
    }

    /**
     * X.696 defines a variable-size number as one or more octets (3.7.11, 3.7.12), and the long
     * forms of the length determinant (8.6.5) and of an ENUMERATED (11.4) carry 1 to 127 subsequent
     * octets. The decoder used to read an empty group as zero in all of them: INTEGER with a
     * determinant of 0, an ENUMERATED long form of 0 octets, a length determinant long form of 0
     * octets, and a sequence-of quantity of 0 octets. Each is rejected now; the one-octet zero of
     * each form still decodes.
     */
    public void testZeroOctetNumbersRejected()
        throws IOException
    {
        Element unsigned = OERDefinition.integer().rangeToMAXFrom(0).build();
        Element signed = OERDefinition.integer().build();
        Element enumerated = OERDefinition.enumeration("a", "b").build();
        Element octets = OERDefinition.octets().build();
        Element seqOf = OERDefinition.seqof(OERDefinition.bool()).build();

        assertRejected("unsigned INTEGER with no octets", unsigned, new byte[]{0x00});
        assertRejected("signed INTEGER with no octets", signed, new byte[]{0x00});
        assertRejected("ENUMERATED long form with no octets", enumerated, new byte[]{(byte)0x80});
        assertRejected("length determinant long form with no octets", octets, new byte[]{(byte)0x80});
        assertRejected("sequence-of quantity with no octets", seqOf, new byte[]{0x00});

        assertNotNull(OERInputStream.parse(new byte[]{0x01, 0x00}, unsigned));
        assertNotNull(OERInputStream.parse(new byte[]{0x01, 0x00}, signed));
        assertNotNull(OERInputStream.parse(new byte[]{0x00}, enumerated));
        assertNotNull(OERInputStream.parse(new byte[]{(byte)0x81, 0x00}, enumerated));
        assertNotNull(OERInputStream.parse(new byte[]{0x00}, octets));
        assertNotNull(OERInputStream.parse(new byte[]{(byte)0x81, 0x00}, octets));
        assertNotNull(OERInputStream.parse(new byte[]{0x01, 0x00}, seqOf));
    }

    /** The compatibility assertion: well-formed encodings are unaffected. */
    public void testWellFormedStillParses()
        throws IOException
    {
        assertNotNull(OERInputStream.parse(new byte[]{(byte)0x81, 0x00}, choiceOfTwo()));

        // extension present with a one-bit bitmap, and the same bitmap with the bit clear
        assertNotNull(OERInputStream.parse(
            new byte[]{(byte)0x80, 0x00, 0x02, 0x07, (byte)0x80, 0x01, 0x00}, seqWithExtension()));
        assertNotNull(OERInputStream.parse(
            new byte[]{(byte)0x80, 0x00, 0x02, 0x07, 0x00}, seqWithExtension()));
        assertNotNull(OERInputStream.parse(new byte[]{0x00, 0x00}, seqWithExtension()));

        assertNotNull(OERInputStream.parse(new byte[]{0x03, 0x61, 0x62, 0x63},
            OERDefinition.octets().build()));
    }
}
