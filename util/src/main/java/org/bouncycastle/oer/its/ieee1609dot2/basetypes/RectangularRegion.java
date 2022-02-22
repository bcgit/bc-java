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

    private RectangularRegion(ASN1Sequence s)
    {
        if (s.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        northWest = TwoDLocation.getInstance(s.getObjectAt(0));
        southEast = TwoDLocation.getInstance(s.getObjectAt(1));

    }


    public static RectangularRegion getInstance(Object o)
    {
        if (o instanceof RectangularRegion)
        {
            return (RectangularRegion)o;
        }

        if (o != null)
        {
            return new RectangularRegion(ASN1Sequence.getInstance(o));
        }

        return null;

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

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private TwoDLocation northWest;
        private TwoDLocation southEast;

        public Builder setNorthWest(TwoDLocation northWest)
        {
            this.northWest = northWest;
            return this;
        }

        public Builder setSouthEast(TwoDLocation southEast)
        {
            this.southEast = southEast;
            return this;
        }

        public RectangularRegion createRectangularRegion()
        {
            return new RectangularRegion(northWest, southEast);
        }
    }

}