package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * ExtendedFailInfo ::= SEQUENCE {
 * failInfoOID            OBJECT IDENTIFIER,
 * failInfoValue          ANY DEFINED BY failInfoOID
 * }
 */
public class ExtendedFailInfo
    extends ASN1Object
{

    private final ASN1ObjectIdentifier failInfoOID;
    private final ASN1Encodable failInfoValue;

    public ExtendedFailInfo(ASN1ObjectIdentifier failInfoOID, ASN1Encodable failInfoValue)
    {
        this.failInfoOID = failInfoOID;
        this.failInfoValue = failInfoValue;
    }

    public static ExtendedFailInfo getInstance(Object obj)
    {
        if (obj instanceof ExtendedFailInfo)
        {
            return (ExtendedFailInfo)obj;
        }

        if (obj instanceof ASN1Encodable)
        {
            ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();
            if (asn1Value instanceof ASN1Sequence)
            {
                return new ExtendedFailInfo(
                    (ASN1ObjectIdentifier)((ASN1Sequence)asn1Value).getObjectAt(0),
                    ((ASN1Sequence)asn1Value).getObjectAt(1)
                );
            }
        }
        throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{failInfoOID, failInfoValue});
    }
}
