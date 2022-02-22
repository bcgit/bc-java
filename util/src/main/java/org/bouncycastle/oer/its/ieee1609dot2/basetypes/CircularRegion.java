package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * <pre>
 *     CircularRegion ::= SEQUENCE {
 *         center TwoDLocation,
 *         radius Uint16
 *     }
 * </pre>
 */
public class CircularRegion
    extends ASN1Object
    implements RegionInterface
{

    private final TwoDLocation center;
    private final UINT16 radius;

    public CircularRegion(TwoDLocation center, UINT16 radius)
    {
        this.center = center;
        this.radius = radius;
    }

    private CircularRegion(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        this.center = TwoDLocation.getInstance(sequence.getObjectAt(0));
        this.radius = UINT16.getInstance(sequence.getObjectAt(1));
    }

    public static CircularRegion getInstance(Object o)
    {
        if (o instanceof CircularRegion)
        {
            return (CircularRegion)o;
        }
        if (o != null)
        {
            return new CircularRegion(ASN1Sequence.getInstance(o));
        }

        return null;

    }

    public TwoDLocation getCenter()
    {
        return center;
    }

    public UINT16 getRadius()
    {
        return radius;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(center, radius);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {

        private TwoDLocation center;
        private UINT16 radius;

        public Builder setCenter(TwoDLocation center)
        {
            this.center = center;
            return this;
        }

        public Builder setRadius(UINT16 radius)
        {
            this.radius = radius;
            return this;
        }

        public CircularRegion createCircularRegion()
        {
            return new CircularRegion(center, radius);
        }
    }
}