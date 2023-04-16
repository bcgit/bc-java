package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
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

    private final List<TwoDLocation> twoDLocations;

    public PolygonalRegion(List<TwoDLocation> locations)
    {
        twoDLocations = Collections.unmodifiableList(locations);
    }

    private PolygonalRegion(ASN1Sequence s)
    {
        ArrayList<TwoDLocation> l = new ArrayList<TwoDLocation>();
        for (Iterator<ASN1Encodable> it = s.iterator(); it.hasNext(); )
        {
            l.add(TwoDLocation.getInstance(it.next()));
        }
        twoDLocations = Collections.unmodifiableList(l);
    }


    public static PolygonalRegion getInstance(Object o)
    {
        if (o instanceof PolygonalRegion)
        {
            return (PolygonalRegion)o;
        }
        else if (o != null)
        {
            return new PolygonalRegion(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public List<TwoDLocation> getTwoDLocations()
    {
        return twoDLocations;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(twoDLocations);
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
