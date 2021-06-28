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

    public BitmapSspRange(ASN1OctetString sspValue, ASN1OctetString sspBitmask)
    {
        this.sspValue = sspValue;
        this.sspBitmask = sspBitmask;
    }

    public static BitmapSspRange getInstance(Object o)
    {
        if (o instanceof BitmapSspRange)
        {
            return (BitmapSspRange)o;
        }
        else if (o != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(o);
            return new BitmapSspRange(
                ASN1OctetString.getInstance(seq.getObjectAt(0)),
                ASN1OctetString.getInstance(seq.getObjectAt(1)));
        }

        return null;
    }

    public ASN1OctetString getSspValue()
    {
        return sspValue;
    }

    public ASN1OctetString getSspBitmask()
    {
        return sspBitmask;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(sspValue, sspBitmask);
    }
}
