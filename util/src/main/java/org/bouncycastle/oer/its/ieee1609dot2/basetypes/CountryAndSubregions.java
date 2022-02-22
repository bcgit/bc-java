package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * CountryAndSubregions ::= SEQUENCE {
 * country              CountryOnly,
 * regionAndSubregions  SequenceOfRegionAndSubregions
 * }
 */
public class CountryAndSubregions
    extends ASN1Object
{

    private final CountryOnly country;
    private final SequenceOfRegionAndSubregions regionAndSubregions;

    public CountryAndSubregions(CountryOnly countryOnly, SequenceOfRegionAndSubregions regionAndSubregions)
    {
        this.country = countryOnly;
        this.regionAndSubregions = regionAndSubregions;
    }

    private CountryAndSubregions(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        country = CountryOnly.getInstance(sequence.getObjectAt(0));
        regionAndSubregions = SequenceOfRegionAndSubregions.getInstance(sequence.getObjectAt(1));
    }

    public static CountryAndSubregions getInstance(Object o)
    {
        if (o instanceof CountryAndSubregions)
        {
            return (CountryAndSubregions)o;
        }

        if (o != null)
        {
            return new CountryAndSubregions(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public CountryOnly getCountry()
    {
        return country;
    }

    public SequenceOfRegionAndSubregions getRegionAndSubregions()
    {
        return regionAndSubregions;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{country, regionAndSubregions});
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private CountryOnly country;
        private SequenceOfRegionAndSubregions regionAndSubregions;

        public Builder setCountry(CountryOnly country)
        {
            this.country = country;
            return this;
        }

        public Builder setRegionAndSubregions(SequenceOfRegionAndSubregions regionAndSubregions)
        {
            this.regionAndSubregions = regionAndSubregions;
            return this;
        }

        public CountryAndSubregions createCountryAndSubregions()
        {
            return new CountryAndSubregions(country, regionAndSubregions);
        }

    }

}
