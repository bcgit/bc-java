package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

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
    private final Uint16 radius;

    public CircularRegion(TwoDLocation center, Uint16 radius)
    {
        this.center = center;
        this.radius = radius;
    }

    public static CircularRegion getInstance(Object o)
    {
        if (o instanceof CircularRegion)
        {
            return (CircularRegion)o;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(o);

        return new CircularRegion(
            TwoDLocation.getInstance(seq.getObjectAt(0)),
            Uint16.getInstance(seq.getObjectAt(1))
        );

    }

    public TwoDLocation getCenter()
    {
        return center;
    }

    public Uint16 getRadius()
    {
        return radius;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(center, radius);
    }

    public static class Builder
    {

        private TwoDLocation center;
        private Uint16 radius;

        public Builder setCenter(TwoDLocation center)
        {
            this.center = center;
            return this;
        }

        public Builder setRadius(Uint16 radius)
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