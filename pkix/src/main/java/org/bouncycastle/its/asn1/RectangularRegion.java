package org.bouncycastle.its.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * <pre>
 *     RectangularRegion ::= SEQUENCE {
 *         northWest TwoDLocation,
 *         southEast TwoDLocation
 *     }
 * </pre>
 */
public class RectangularRegion
    extends ASN1Object
{
    private RectangularRegion(ASN1Sequence seq)
    {

    }

    public static RectangularRegion getInstance(Object o)
    {
        if (o instanceof RectangularRegion)
        {
            return (RectangularRegion)o;
        }
        else if (o != null)
        {
            return new RectangularRegion(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return null;
    }
}