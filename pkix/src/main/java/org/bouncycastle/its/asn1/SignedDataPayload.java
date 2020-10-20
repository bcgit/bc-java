package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     SignedDataPayload ::= SEQUENCE {
 *         data Ieee1609Dot2Data OPTIONAL,
 *         extDataHash HashedData OPTIONAL,
 *         ...
 *     }
 * </pre>
 */
public class SignedDataPayload
    extends ASN1Object
{
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }
}
