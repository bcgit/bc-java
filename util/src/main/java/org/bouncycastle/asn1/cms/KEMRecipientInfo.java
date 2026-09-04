package org.bouncycastle.asn1.cms;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.BigIntegers;

/**
 * <p>
 * Defined in <a href="https://datatracker.ietf.org/doc/rfc9629/">RFC 9629</a>.
 * </p>
 * <pre>
 *   KEMRecipientInfo ::= SEQUENCE {
 *     version CMSVersion,  -- always set to 0
 *     rid RecipientIdentifier,
 *     kem KEMAlgorithmIdentifier,
 *     kemct OCTET STRING,
 *     kdf KeyDerivationAlgorithmIdentifier,
 *     kekLength INTEGER (1..65535),
 *     ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL,
 *     wrap KeyEncryptionAlgorithmIdentifier,
 *     encryptedKey EncryptedKey }
 * </pre>
 */
public class KEMRecipientInfo
    extends ASN1Object
{
    private static final BigInteger MAX_KEK_LENGTH = BigInteger.valueOf(65535);

    private final ASN1Integer cmsVersion;
    private final RecipientIdentifier rid;
    private final AlgorithmIdentifier kem;
    private final ASN1OctetString kemct;
    private final AlgorithmIdentifier kdf;
    private final ASN1Integer kekLength;
    private final ASN1OctetString ukm;
    private final AlgorithmIdentifier wrap;
    private final ASN1OctetString encryptedKey;

    public KEMRecipientInfo(RecipientIdentifier rid, AlgorithmIdentifier kem, ASN1OctetString kemct,
                            AlgorithmIdentifier kdf, ASN1Integer kekLength, ASN1OctetString ukm, AlgorithmIdentifier wrap, ASN1OctetString encryptedKey)
    {
        if (kem == null)
        {
            throw new NullPointerException("kem cannot be null");
        }
        if (wrap == null)
        {
            throw new NullPointerException("wrap cannot be null");
        }
        checkKekLength(kekLength);
        this.cmsVersion = ASN1Integer.ZERO;
        this.rid = rid;
        this.kem = kem;
        this.kemct = kemct;
        this.kdf = kdf;
        this.kekLength = kekLength;
        this.ukm = ukm;
        this.wrap = wrap;
        this.encryptedKey = encryptedKey;
    }

    public static KEMRecipientInfo getInstance(Object o)
    {
        if (o instanceof KEMRecipientInfo)
        {
            return (KEMRecipientInfo)o;
        }
        else if (o != null)
        {
            return new KEMRecipientInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private KEMRecipientInfo(ASN1Sequence seq)
    {
        if (seq.size() < 8 || seq.size() > 9)
        {
            throw new IllegalArgumentException("bad sequence size: " + seq.size());
        }

        cmsVersion = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (!cmsVersion.hasValue(0))
        {
            throw new IllegalArgumentException("version must be 0");
        }
        rid = RecipientIdentifier.getInstance(seq.getObjectAt(1));
        kem = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
        kemct = ASN1OctetString.getInstance(seq.getObjectAt(3));
        kdf = AlgorithmIdentifier.getInstance(seq.getObjectAt(4));
        kekLength = ASN1Integer.getInstance(seq.getObjectAt(5));

        checkKekLength(kekLength);

        int elt = 6;
        if (seq.getObjectAt(6) instanceof ASN1TaggedObject)
        {
            if (seq.size() != 9)
            {
                throw new IllegalArgumentException("bad sequence size: " + seq.size());
            }
            ukm = ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(elt++)), true);
        }
        else
        {
            if (seq.size() != 8)
            {
                throw new IllegalArgumentException("bad sequence size: " + seq.size());
            }
            ukm = null;
        }
        wrap = AlgorithmIdentifier.getInstance(seq.getObjectAt(elt++));
        encryptedKey = ASN1OctetString.getInstance(seq.getObjectAt(elt++));
    }

    /**
     * Check the kekLength is in the ASN.1 range (1..65535). The comparison is made on the
     * BigInteger value - an out of range value may be too large for an int, and calling
     * ASN1Integer.intValueExact() on one of those throws ArithmeticException before the
     * range check that is meant to reject it can be applied.
     */
    private static void checkKekLength(ASN1Integer kekLength)
    {
        BigInteger value = kekLength.getValue();

        if (value.compareTo(MAX_KEK_LENGTH) > 0)
        {
            throw new IllegalArgumentException("kekLength must be <= 65535");
        }
        if (value.compareTo(BigIntegers.ONE) < 0)
        {
            throw new IllegalArgumentException("kekLength must be >= 1");
        }
    }

    public RecipientIdentifier getRecipientIdentifier()
    {
        return rid;
    }

    public AlgorithmIdentifier getKem()
    {
        return kem;
    }

    public ASN1OctetString getKemct()
    {
        return kemct;
    }

    public AlgorithmIdentifier getKdf()
    {
        return kdf;
    }

    /**
     * Return the size of the key-encryption key, in octets. RFC 9629 requires this to be
     * consistent with the algorithm named in the wrap field.
     *
     * @return the kekLength field, always in the range 1..65535.
     */
    public int getKekLength()
    {
        return kekLength.intValueExact();
    }

    public AlgorithmIdentifier getWrap()
    {
        return wrap;
    }

    public byte[] getUkm()
    {
        if (ukm == null)
        {
            return null;
        }

        return ukm.getOctets();
    }

    public ASN1OctetString getEncryptedKey()
    {
        return encryptedKey;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(cmsVersion);
        v.add(rid);
        v.add(kem);
        v.add(kemct);
        v.add(kdf);
        v.add(kekLength);
        if (ukm != null)
        {
            v.add(new DERTaggedObject(true, 0, ukm));
        }
        v.add(wrap);
        v.add(encryptedKey);

        return new DERSequence(v);
    }
}
