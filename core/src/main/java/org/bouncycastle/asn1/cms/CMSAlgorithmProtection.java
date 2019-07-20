package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * From RFC 6211
 * <pre>
 * CMSAlgorithmProtection ::= SEQUENCE {
 *    digestAlgorithm         DigestAlgorithmIdentifier,
 *    signatureAlgorithm  [1] SignatureAlgorithmIdentifier OPTIONAL,
 *    macAlgorithm        [2] MessageAuthenticationCodeAlgorithm
 *                                     OPTIONAL
 * }
 * (WITH COMPONENTS { signatureAlgorithm PRESENT,
 *                    macAlgorithm ABSENT } |
 *  WITH COMPONENTS { signatureAlgorithm ABSENT,
 *                    macAlgorithm PRESENT })
 * </pre>
 */
public class CMSAlgorithmProtection
    extends ASN1Object
{
    public static final int SIGNATURE = 1;
    public static final int MAC = 2;

    private final AlgorithmIdentifier digestAlgorithm;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final AlgorithmIdentifier macAlgorithm;

    public CMSAlgorithmProtection(AlgorithmIdentifier digestAlgorithm, int type, AlgorithmIdentifier algorithmIdentifier)
    {
        if (digestAlgorithm == null || algorithmIdentifier == null)
        {
            throw new NullPointerException("AlgorithmIdentifiers cannot be null");
        }

        this.digestAlgorithm = digestAlgorithm;

        if (type == 1)
        {
            this.signatureAlgorithm = algorithmIdentifier;
            this.macAlgorithm = null;
        }
        else if (type == 2)
        {
            this.signatureAlgorithm = null;
            this.macAlgorithm = algorithmIdentifier;
        }
        else
        {
            throw new IllegalArgumentException("Unknown type: " + type);
        }
    }

    private CMSAlgorithmProtection(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("Sequence wrong size: One of signatureAlgorithm or macAlgorithm must be present");
        }

        this.digestAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));

        ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(sequence.getObjectAt(1));
        if (tagged.getTagNo() == 1)
        {
            this.signatureAlgorithm = AlgorithmIdentifier.getInstance(tagged, false);
            this.macAlgorithm = null;
        }
        else if (tagged.getTagNo() == 2)
        {
            this.signatureAlgorithm = null;

            this.macAlgorithm = AlgorithmIdentifier.getInstance(tagged, false);
        }
        else
        {
            throw new IllegalArgumentException("Unknown tag found: " + tagged.getTagNo());
        }
    }

    public static CMSAlgorithmProtection getInstance(
        Object obj)
    {
        if (obj instanceof CMSAlgorithmProtection)
        {
            return (CMSAlgorithmProtection)obj;
        }
        else if (obj != null)
        {
            return new CMSAlgorithmProtection(ASN1Sequence.getInstance(obj));
        }

        return null;
    }


    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    public AlgorithmIdentifier getMacAlgorithm()
    {
        return macAlgorithm;
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(digestAlgorithm);
        if (signatureAlgorithm != null)
        {
            v.add(new DERTaggedObject(false, 1, signatureAlgorithm));
        }
        if (macAlgorithm != null)
        {
            v.add(new DERTaggedObject(false, 2, macAlgorithm));
        }

        return new DERSequence(v);
    }
}
