package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

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
    implements RegionInterface
{
    private final TwoDLocation northWest;
    private final TwoDLocation southEast;

    public RectangularRegion(TwoDLocation northWest, TwoDLocation southEast)
    {
        this.northWest = northWest;
        this.southEast = southEast;
    }

    public static RectangularRegion getInstance(Object o)
    {
        if (o instanceof RectangularRegion)
        {
            return (RectangularRegion)o;
        }
        else
        {
            ASN1Sequence seg = ASN1Sequence.getInstance(o);
            return new RectangularRegion(TwoDLocation.getInstance(seg.getObjectAt(0)),
                TwoDLocation.getInstance(seg.getObjectAt(1)));
        }

    }

    public TwoDLocation getNorthWest()
    {
        return northWest;
    }

    public TwoDLocation getSouthEast()
    {
        return southEast;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{northWest, southEast});
    }
}