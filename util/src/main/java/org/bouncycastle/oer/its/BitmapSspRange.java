package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * <pre>
 *     BitmapSspRange ::= SEQUENCE {
 *         sspValue OCTET STRING (SIZE(1..32)),
 *         sspBitmask OCTET STRING (SIZE(1..32))
 *     }
 * </pre>
 */
public class BitmapSspRange
    extends ASN1Object
{
    private final ASN1OctetString sspValue;
    private final ASN1OctetString sspBitmask;

    private BitmapSspRange(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence with sspValue and sspBitmask");
        }

        sspValue =
            ASN1OctetString.getInstance(seq.getObjectAt(0));
        sspBitmask =
            ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static BitmapSspRange getInstance(Object o)
    {
        if (o instanceof BitmapSspRange)
        {
            return (BitmapSspRange)o;
        }
        else if (o != null)
        {
            return new BitmapSspRange(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(sspValue, sspBitmask);
    }
}
