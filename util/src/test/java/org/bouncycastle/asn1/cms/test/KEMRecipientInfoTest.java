package org.bouncycastle.asn1.cms.test;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
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
}
