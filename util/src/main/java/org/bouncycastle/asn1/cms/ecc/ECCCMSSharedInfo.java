package org.bouncycastle.asn1.cms.ecc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *     ECC-CMS-SharedInfo ::= SEQUENCE {
 *        keyInfo AlgorithmIdentifier,
 *        entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
 *        suppPubInfo [2] EXPLICIT OCTET STRING   }
 * </pre>
 */
public class ECCCMSSharedInfo
    extends ASN1Object
{

    private final AlgorithmIdentifier keyInfo;
    private final byte[] entityUInfo;
    private final byte[] suppPubInfo;

    public ECCCMSSharedInfo(
        AlgorithmIdentifier keyInfo,
        byte[] entityUInfo,
        byte[] suppPubInfo)
    {
        this.keyInfo = keyInfo;
        this.entityUInfo = Arrays.clone(entityUInfo);
        this.suppPubInfo = Arrays.clone(suppPubInfo);
    }

    public ECCCMSSharedInfo(
        AlgorithmIdentifier keyInfo,
        byte[] suppPubInfo)
    {
        this.keyInfo = keyInfo;
        this.entityUInfo = null;
        this.suppPubInfo = Arrays.clone(suppPubInfo);
    }

    private ECCCMSSharedInfo(
        ASN1Sequence seq)
    {
        this.keyInfo = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            this.entityUInfo = null;
            this.suppPubInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true).getOctets();
        }
        else
        {
            this.entityUInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true).getOctets();
            this.suppPubInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(2), true).getOctets();
        }
    }

    /**
     * Return an ECC-CMS-SharedInfo object from a tagged object.
     *
     * @param obj      the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *                 tagged false otherwise.
     * @throws IllegalArgumentException if the object held by the
     *                                  tagged object cannot be converted.
     */
    public static ECCCMSSharedInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ECCCMSSharedInfo getInstance(
        Object obj)
    {
        if (obj instanceof ECCCMSSharedInfo)
        {
            return (ECCCMSSharedInfo)obj;
        }
        else if (obj != null)
        {
            return new ECCCMSSharedInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }


    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(keyInfo);

        if (entityUInfo != null)
        {
            v.add(new DERTaggedObject(true, 0, new DEROctetString(entityUInfo)));
        }

        v.add(new DERTaggedObject(true, 2, new DEROctetString(suppPubInfo)));

        return new DERSequence(v);
    }
}
