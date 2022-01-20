package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * CountryAndRegions ::= SEQUENCE {
 * countryOnly  CountryOnly,
 * regions      SequenceOfUint8
 * }
 */
public class CountryAndRegions
    extends ASN1Object
    implements RegionInterface
{

    private final CountryOnly countryOnly;
    private final List<Region> regions;

    public CountryAndRegions(CountryOnly countryOnly, List<Region> regionList)
    {
        this.countryOnly = countryOnly;
        this.regions = Collections.unmodifiableList(regionList);
    }


    private CountryAndRegions(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalStateException("expected sequence size of two");
        }
        countryOnly = CountryOnly.getInstance(sequence.getObjectAt(0));
        regions = ItsUtils.fillList(Region.class, ASN1Sequence.getInstance(sequence.getObjectAt(1)));
    }

    public static CountryAndRegions getInstance(Object object)
    {
        if (object instanceof CountryAndRegions)
        {
            return (CountryAndRegions)object;
        }

        if (object != null)
        {
            return new CountryAndRegions(ASN1Sequence.getInstance(object));
        }

        return null;


    }

    public static CountryAndRegionsBuilder builder()
    {
        return new CountryAndRegionsBuilder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(countryOnly, ItsUtils.toSequence(regions));
    }

    public CountryOnly getCountryOnly()
    {
        return countryOnly;
    }

    public List<Region> getRegions()
    {
        return regions;
    }

    public static class CountryAndRegionsBuilder
    {

        private final List<Region> regionList;
        private CountryOnly countryOnly;

        public CountryAndRegionsBuilder()
        {
            regionList = new ArrayList<Region>();
        }

        public CountryAndRegionsBuilder setCountryOnly(CountryOnly countryOnly)
        {
            this.countryOnly = countryOnly;
            return this;
        }

        public CountryAndRegionsBuilder setRegionList(List<Region> regionList)
        {
            this.regionList.addAll(regionList);
            return this;
        }

        public CountryAndRegionsBuilder addRegion(Region region)
        {

            this.regionList.add(region);
            return this;
        }

        public CountryAndRegions build()
        {
            return new CountryAndRegions(countryOnly, regionList);
        }
    }


}
