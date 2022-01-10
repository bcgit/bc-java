package org.bouncycastle.oer.its;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

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


    public static CountryAndRegions getInstance(Object object)
    {
        if (object instanceof CountryAndRegions)
        {
            return (CountryAndRegions)object;
        }

        ASN1Sequence sequence = ASN1Sequence.getInstance(object);

        CountryOnly countryOnly = CountryOnly.getInstance(sequence.getObjectAt(0));
        ASN1Sequence regions = ASN1Sequence.getInstance(sequence.getObjectAt(1));

        return new CountryAndRegions(countryOnly, Utils.fillList(Region.class, regions));

    }

    public static CountryAndRegionsBuilder builder()
    {
        return new CountryAndRegionsBuilder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(countryOnly, Utils.toSequence(regions));
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

        private CountryOnly countryOnly;
        private final List<Region> regionList;

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
