package org.bouncycastle.oer.its;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * RegionAndSubregions ::= SEQUENCE {
 * region      Uint8,
 * subregions  SequenceOfUint16
 * }
 */
public class RegionAndSubregions
    extends ASN1Object
    implements RegionInterface
{
    private final Region region;
    private final List<Uint16> subRegions;


    public RegionAndSubregions(Region region, List<Uint16> subRegions)
    {
        this.region = region;
        this.subRegions = Collections.unmodifiableList(subRegions);
    }

    public static RegionAndSubregions getInstance(Object o)
    {
        if (o instanceof RegionAndSubregions)
        {
            return (RegionAndSubregions)o;
        }
        else
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(0);
            Builder builder = new Builder();
            builder.setRegion(Region.getInstance(seq.getObjectAt(0)));
            ASN1Sequence subRegionsSeq = ASN1Sequence.getInstance(seq.getObjectAt(1));
            for (Iterator it = subRegionsSeq.iterator(); it.hasNext(); )
            {
                builder.setSubRegion(Uint16.getInstance(it.next()));
            }
            return builder.createRegionAndSubregions();
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(region, Utils.toSequence(subRegions));
    }

    public static class Builder
    {

        private Region region;
        private List<Uint16> subRegions;

        public Builder setRegion(Region region)
        {
            this.region = region;
            return this;
        }

        public Builder setSubRegions(List<Uint16> subRegions)
        {
            this.subRegions = subRegions;
            return this;
        }

        public Builder setSubRegion(Uint16... subRegions)
        {
            this.subRegions.addAll(Arrays.asList(subRegions));
            return this;
        }

        public RegionAndSubregions createRegionAndSubregions()
        {
            return new RegionAndSubregions(region, subRegions);
        }
    }

}
