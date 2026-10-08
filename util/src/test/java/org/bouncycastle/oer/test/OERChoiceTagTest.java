package org.bouncycastle.oer.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OERDefinition;
import org.bouncycastle.oer.OERInputStream;
import org.bouncycastle.oer.OEROutputStream;
import org.bouncycastle.util.encoders.Hex;

/**
 * X.696 sec. 8.7.2.2 puts a CHOICE tag number below 63 in the first octet; 8.7.2.3 sets those six
 * bits for 63 and up and continues in 7-bit groups, most significant first, bit 8 as the
 * continuation flag. The encoder used the single octet up to and including 63, and wrote the
 * groups top-aligned from bit 31 rather than bottom-aligned, so no tag from 63 up round-tripped.
 */
public class OERChoiceTagTest
    extends TestCase
{
    private static final int ALTERNATIVES = 20000;

    private static Element wideChoice()
    {
        Object[] alternatives = new Object[ALTERNATIVES];
        for (int i = 0; i != ALTERNATIVES; i++)
        {
            alternatives[i] = OERDefinition.bool();
        }
        return OERDefinition.choice(alternatives).build();
    }

    public void testTagNumbersAcrossTheLongFormBoundary()
        throws IOException
    {
        Element schema = wideChoice();
        check(schema, 0, "80FF");
        check(schema, 62, "BEFF");
        check(schema, 63, "BF3FFF");
        check(schema, 64, "BF40FF");
        check(schema, 127, "BF7FFF");
        check(schema, 128, "BF8100FF");
        check(schema, 16383, "BFFF7FFF");
        check(schema, 16384, "BF818000FF");
    }

    private static void check(Element schema, int tag, String expectedHex)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OEROutputStream oerOut = new OEROutputStream(bOut);
        oerOut.write(new DERTaggedObject(tag, ASN1Boolean.TRUE), schema);
        byte[] encoding = bOut.toByteArray();
        assertEquals("tag " + tag, expectedHex, Hex.toHexString(encoding).toUpperCase());

        ASN1TaggedObject decoded = ASN1TaggedObject.getInstance(OERInputStream.parse(encoding, schema));
        assertEquals("tag " + tag, tag, decoded.getTagNo());
        assertTrue("tag " + tag, ASN1Boolean.getInstance(decoded.getBaseObject()).isTrue());
    }
}
