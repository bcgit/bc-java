package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

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
    private final SequenceOfUint8 regions;

    public CountryAndRegions(CountryOnly countryOnly, SequenceOfUint8 regionList)
    {
        this.countryOnly = countryOnly;
        this.regions = SequenceOfUint8.getInstance(regionList);
    }


    private CountryAndRegions(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }
        countryOnly = CountryOnly.getInstance(sequence.getObjectAt(0));
        regions = SequenceOfUint8.getInstance(sequence.getObjectAt(1));
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

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(countryOnly, regions);
    }

    public CountryOnly getCountryOnly()
    {
        return countryOnly;
    }

    public SequenceOfUint8 getRegions()
    {
        return regions;
    }

    public static class Builder
    {

        private SequenceOfUint8 regionList;
        private CountryOnly countryOnly;

        public Builder()
        {
        }

        public Builder setCountryOnly(CountryOnly countryOnly)
        {
            this.countryOnly = countryOnly;
            return this;
        }

        public Builder setRegions(SequenceOfUint8 regionList)
        {
            this.regionList = regionList;
            return this;
        }

        public CountryAndRegions createCountryAndRegions()
        {
            return new CountryAndRegions(countryOnly, regionList);
        }
    }


}
