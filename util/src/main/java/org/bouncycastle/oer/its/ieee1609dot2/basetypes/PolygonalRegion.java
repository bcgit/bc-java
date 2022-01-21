package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * <pre>
 *     SEQUENCE SIZE(3..MAX) OF TwoDLocation
 * </pre>
 */
public class PolygonalRegion
    extends ASN1Object
    implements RegionInterface
{

    private final List<TwoDLocation> points;

    public PolygonalRegion(List<TwoDLocation> locations)
    {
        points = Collections.unmodifiableList(locations);
    }

    public static PolygonalRegion getInstance(Object o)
    {
        if (o instanceof PolygonalRegion)
        {
            return (PolygonalRegion)o;
        }
        else if (o != null)
        {
            return new PolygonalRegion(ItsUtils.fillList(TwoDLocation.class, ASN1Sequence.getInstance(o)));
        }
        return null;
    }

    public List<TwoDLocation> getPoints()
    {
        return points;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(points);
    }

    public static class Builder
    {

        private List<TwoDLocation> locations = new ArrayList<TwoDLocation>();

        public Builder setLocations(List<TwoDLocation> locations)
        {
            this.locations = locations;
            return this;
        }

        public Builder setLocations(TwoDLocation... locations)
        {
            this.locations.addAll(Arrays.asList(locations));
            return this;
        }

        public PolygonalRegion createPolygonalRegion()
        {
            return new PolygonalRegion(locations);
        }
    }
}
