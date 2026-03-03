package org.bouncycastle.asn1.plants;

import org.bouncycastle.asn1.*;

/**
 * ASN.1 representation of a cosigner signature used in {@link MTCProof}.
 *
 * <pre>
 * MTCSignature ::= SEQUENCE {
 *     cosigner_id   ASN1RelativeOID,
 *     signature     OCTET STRING
 * }
 * </pre>
 */
public class MTCSignature extends ASN1Object
{
    private final ASN1RelativeOID cosignerId;
    private final ASN1OctetString signature;

    public static MTCSignature getInstance(Object obj)
    {
        if (obj instanceof MTCSignature)
        {
            return (MTCSignature)obj;
        }
        else if (obj != null)
        {
            return new MTCSignature(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private MTCSignature(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Invalid MTCSignature sequence size");
        }

        this.cosignerId = ASN1RelativeOID.getInstance(seq.getObjectAt(0));
        this.signature = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public MTCSignature(ASN1RelativeOID cosignerId, ASN1OctetString signature)
    {
        this.cosignerId = cosignerId;
        this.signature = signature;
    }

    public ASN1RelativeOID getCosignerId()
    {
        return cosignerId;
    }

    public ASN1OctetString getSignature()
    {
        return signature;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(cosignerId);
        v.add(signature);

        return new DERSequence(v);
    }
}
