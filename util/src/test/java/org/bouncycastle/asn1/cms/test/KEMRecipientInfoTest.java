package org.bouncycastle.asn1.cms.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Base64;

public class KEMRecipientInfoTest
    extends TestCase
{
    private static byte[] outOfRangeEnc = Base64.decode("MDoCAQCAADALBglghkgBZQMEBAEEADAMBgorgQUQhkgJLAECAgMKrmCgAgQAMAsGCWCGSAFlAwQBMAQA");

    public void testOutOfRange()
        throws Exception
    {
        try
        {
            new KEMRecipientInfo(
                new RecipientIdentifier(new DEROctetString(new byte[0])),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_512),
                new DEROctetString(new byte[0]),
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3),
                ASN1Integer.valueOf(700000), new DEROctetString(new byte[0]),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_wrap_pad),
                new DEROctetString(new byte[0]));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("kekLength must be <= 65535", e.getMessage());
        }

        try
        {
            KEMRecipientInfo.getInstance(ASN1Primitive.fromByteArray(outOfRangeEnc));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("kekLength must be <= 65535", e.getMessage());
        }
    }

    public void testNullWrap()
        throws Exception
    {
        try
        {
            new KEMRecipientInfo(
                new RecipientIdentifier(new DEROctetString(new byte[0])),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_512),
                new DEROctetString(new byte[0]),
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3),
                ASN1Integer.valueOf(7000), new DEROctetString(new byte[0]),
                null,
                new DEROctetString(new byte[0]));
            fail("no exception");
        }
        catch (NullPointerException e)
        {
            assertEquals("wrap cannot be null", e.getMessage());
        }
    }

    public void testNullKem()
        throws Exception
    {
        try
        {
            new KEMRecipientInfo(
                new RecipientIdentifier(new DEROctetString(new byte[0])),
                null,
                new DEROctetString(new byte[0]),
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3),
                ASN1Integer.valueOf(7000), new DEROctetString(new byte[0]),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_wrap_pad),
                new DEROctetString(new byte[0]));
            fail("no exception");
        }
        catch (NullPointerException e)
        {
            assertEquals("kem cannot be null", e.getMessage());
        }
    }

    public void testSequenceSize()
        throws Exception
    {
        try
        {
            KEMRecipientInfo.getInstance(new DERSequence(new RecipientIdentifier(new DEROctetString(new byte[0]))));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("bad sequence size: 1", e.getMessage());
        }

        try
        {
            ASN1Encodable[] elements = new ASN1Encodable[10];
            for (int i = 0; i != elements.length; i++)
            {
                elements[i] = ASN1Integer.ONE;
            }
            KEMRecipientInfo.getInstance(new DERSequence(elements));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("bad sequence size: 10", e.getMessage());
        }
    }

    public void testZeroKekLength()
        throws Exception
    {
        // RFC 9629: kekLength INTEGER (1..65535) - reject a zero (or negative) length.
        try
        {
            new KEMRecipientInfo(
                new RecipientIdentifier(new DEROctetString(new byte[0])),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_512),
                new DEROctetString(new byte[0]),
                new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3),
                ASN1Integer.valueOf(0), new DEROctetString(new byte[0]),
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_wrap_pad),
                new DEROctetString(new byte[0]));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("kekLength must be >= 1", e.getMessage());
        }

        // Same via the parse path: a well-formed SEQUENCE carrying kekLength == 0.
        ASN1Encodable[] elements = new ASN1Encodable[]{
            ASN1Integer.valueOf(0),                                                 // version
            new RecipientIdentifier(new DEROctetString(new byte[0])),               // rid
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_512),       // kem
            new DEROctetString(new byte[0]),                                        // kemct
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3),               // kdf
            ASN1Integer.valueOf(0),                                                 // kekLength = 0
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_wrap_pad),      // wrap
            new DEROctetString(new byte[0])};                                       // encryptedKey
        try
        {
            KEMRecipientInfo.getInstance(new DERSequence(elements));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("kekLength must be >= 1", e.getMessage());
        }
    }

    public void testBadVersion()
        throws Exception
    {
        // RFC 9629: version is always 0 - a non-zero version on parse must be rejected.
        ASN1Encodable[] elements = new ASN1Encodable[8];
        elements[0] = ASN1Integer.valueOf(1);
        for (int i = 1; i != elements.length; i++)
        {
            elements[i] = ASN1Integer.ONE;
        }
        try
        {
            KEMRecipientInfo.getInstance(new DERSequence(elements));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("version must be 0", e.getMessage());
        }
    }

    /**
     * Build the eight elements of a ukm-less KEMRecipientInfo, with the given kekLength.
     */
    private static ASN1Encodable[] baseElements(ASN1Integer kekLength)
    {
        return new ASN1Encodable[]{
            ASN1Integer.valueOf(0),                                                 // version
            new RecipientIdentifier(new DEROctetString(new byte[0])),               // rid
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_512),       // kem
            new DEROctetString(new byte[0]),                                        // kemct
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3),               // kdf
            kekLength,                                                              // kekLength
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_wrap_pad),      // wrap
            new DEROctetString(new byte[0])};                                       // encryptedKey
    }

    public void testOversizedKekLength()
        throws Exception
    {
        // RFC 9629: kekLength INTEGER (1..65535). A value too large for an int has to be
        // rejected by the range check as well - ASN1Integer.intValueExact() would throw
        // ArithmeticException before the range check could be applied.
        ASN1Integer[] outOfRange = new ASN1Integer[]{
            new ASN1Integer(BigInteger.ONE.shiftLeft(40)),
            new ASN1Integer(BigInteger.ONE.shiftLeft(40).negate())};

        for (int i = 0; i != outOfRange.length; i++)
        {
            String expected = (i == 0) ? "kekLength must be <= 65535" : "kekLength must be >= 1";

            try
            {
                new KEMRecipientInfo(
                    new RecipientIdentifier(new DEROctetString(new byte[0])),
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_512),
                    new DEROctetString(new byte[0]),
                    new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3),
                    outOfRange[i], new DEROctetString(new byte[0]),
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes256_wrap_pad),
                    new DEROctetString(new byte[0]));
                fail("no exception");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals(expected, e.getMessage());
            }

            try
            {
                KEMRecipientInfo.getInstance(new DERSequence(baseElements(outOfRange[i])));
                fail("no exception");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals(expected, e.getMessage());
            }
        }
    }

    public void testUkmSizeMismatch()
        throws Exception
    {
        // RFC 9629: ukm is the optional [0] element, so a sequence carrying it has nine
        // elements and one without it has eight - the size and the tag have to agree, or
        // the fields after the ukm are read at the wrong index.
        ASN1Encodable[] base = baseElements(ASN1Integer.valueOf(32));

        // eight elements, but element 6 is a [0] ukm: wrap and encryptedKey are missing.
        ASN1EncodableVector shortWithUkm = new ASN1EncodableVector();
        for (int i = 0; i != 6; i++)
        {
            shortWithUkm.add(base[i]);
        }
        shortWithUkm.add(new DERTaggedObject(true, 0, new DEROctetString(new byte[]{9, 9})));
        shortWithUkm.add(base[6]);

        try
        {
            KEMRecipientInfo.getInstance(new DERSequence(shortWithUkm));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("bad sequence size: 8", e.getMessage());
        }

        // nine elements with no [0] ukm: there is a trailing element with nothing to be.
        ASN1EncodableVector longWithoutUkm = new ASN1EncodableVector();
        for (int i = 0; i != base.length; i++)
        {
            longWithoutUkm.add(base[i]);
        }
        longWithoutUkm.add(new DEROctetString(new byte[]{7, 7}));

        try
        {
            KEMRecipientInfo.getInstance(new DERSequence(longWithoutUkm));
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("bad sequence size: 9", e.getMessage());
        }
    }

    public void testKekLength()
        throws Exception
    {
        // the eight element form, no ukm.
        KEMRecipientInfo info = KEMRecipientInfo.getInstance(new DERSequence(baseElements(ASN1Integer.valueOf(32))));

        assertEquals(32, info.getKekLength());
        assertNull(info.getUkm());

        // the nine element form, with a ukm - the boundary values of the range still parse.
        ASN1Encodable[] base = baseElements(ASN1Integer.valueOf(1));
        ASN1EncodableVector withUkm = new ASN1EncodableVector();
        for (int i = 0; i != 6; i++)
        {
            withUkm.add(base[i]);
        }
        withUkm.add(new DERTaggedObject(true, 0, new DEROctetString(new byte[]{9, 9})));
        withUkm.add(base[6]);
        withUkm.add(base[7]);

        info = KEMRecipientInfo.getInstance(new DERSequence(withUkm));

        assertEquals(1, info.getKekLength());
        assertTrue(org.bouncycastle.util.Arrays.areEqual(new byte[]{9, 9}, info.getUkm()));

        base = baseElements(ASN1Integer.valueOf(65535));
        assertEquals(65535, KEMRecipientInfo.getInstance(new DERSequence(base)).getKekLength());
    }
}
