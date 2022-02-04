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

    private final CountryOnly countryOnly;
    private final SequenceOfRegionAndSubregions regionAndSubregions;

    public CountryAndSubregions(CountryOnly countryOnly, SequenceOfRegionAndSubregions regionAndSubregions)
    {
        this.countryOnly = countryOnly;
        this.regionAndSubregions = regionAndSubregions;
    }

    private CountryAndSubregions(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("expected sequence size of 2");
        }

        countryOnly = CountryOnly.getInstance(sequence.getObjectAt(0));
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


    public CountryOnly getCountryOnly()
    {
        return countryOnly;
    }

    public SequenceOfRegionAndSubregions getRegionAndSubregions()
    {
        return regionAndSubregions;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{countryOnly, regionAndSubregions});
    }
}
