package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

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
    private final SequenceOfUint16 subRegions;


    public RegionAndSubregions(Region region, List<UINT16> subRegions)
    {
        this.region = region;
        this.subRegions = new SequenceOfUint16(subRegions);
    }

    private RegionAndSubregions(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        region = Region.getInstance(seq.getObjectAt(0));
        subRegions = SequenceOfUint16.getInstance(seq.getObjectAt(1));
    }

    public Region getRegion()
    {
        return region;
    }

    public SequenceOfUint16 getSubRegions()
    {
        return subRegions;
    }

    public static RegionAndSubregions getInstance(Object o)
    {
        if (o instanceof RegionAndSubregions)
        {
            return (RegionAndSubregions)o;
        }

        if (o != null)
        {
            return new RegionAndSubregions(ASN1Sequence.getInstance(o));
        }

        return null;

    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(region, subRegions);
    }

    public static class Builder
    {

        private Region region;
        private List<UINT16> subRegions;

        public Builder setRegion(Region region)
        {
            this.region = region;
            return this;
        }

        public Builder setSubRegions(List<UINT16> subRegions)
        {
            this.subRegions = subRegions;
            return this;
        }

        public Builder setSubRegion(UINT16... subRegions)
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
