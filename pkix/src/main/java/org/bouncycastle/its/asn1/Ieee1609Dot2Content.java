package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     Ieee1609Dot2Content ::= CHOICE {
 *         unsecuredData Opaque,
 *         signedData SignedData,
 *         encryptedData EncryptedData,
 *         signedCertificateRequest Opaque,
 *         ...
 *     }
 * </pre>
 */
public class Ieee1609Dot2Content
    extends ASN1Object
    implements ASN1Choice
{
    public static Ieee1609Dot2Content getInstance(Object src)
    {
        if (src instanceof Ieee1609Dot2Content)
        {
            return (Ieee1609Dot2Content)src;
        }
        else if (src != null)
        {
            // TODO: need choice processing here
            return getInstance(ASN1Sequence.getInstance(src));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }
}
