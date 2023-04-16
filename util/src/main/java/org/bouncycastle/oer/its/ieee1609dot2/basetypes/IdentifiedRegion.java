package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERTaggedObject;


/**
 * IdentifiedRegion ::= CHOICE {
 * countryOnly           CountryOnly,
 * countryAndRegions     CountryAndRegions,
 * countryAndSubregions  CountryAndSubregions,
 * ...
 * }
 */
public class IdentifiedRegion
    extends ASN1Object
    implements ASN1Choice, RegionInterface
{

    public static final int countryOnly = 0;
    public static final int countryAndRegions = 1;
    public static final int countryAndSubregions = 2;

    private final int choice;
    private final ASN1Encodable identifiedRegion;

    public IdentifiedRegion(int choice, ASN1Encodable region)
    {
        this.choice = choice;
        this.identifiedRegion = region;
    }

    private IdentifiedRegion(ASN1TaggedObject ato)
    {
        this.choice = ato.getTagNo();

        switch (choice)
        {
        case countryOnly:
            identifiedRegion = CountryOnly.getInstance(ato.getExplicitBaseObject());
            break;
        case countryAndRegions:
            identifiedRegion = CountryAndRegions.getInstance(ato.getExplicitBaseObject());
            break;
        case countryAndSubregions:
            identifiedRegion = CountryAndSubregions.getInstance(ato.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static IdentifiedRegion countryOnly(CountryOnly only)
    {
        return new IdentifiedRegion(countryOnly, only);
    }

    public static IdentifiedRegion countryAndRegions(CountryAndRegions value)
    {
        return new IdentifiedRegion(countryAndRegions, value);
    }

    public static IdentifiedRegion countryAndSubregions(CountryAndSubregions countryAndSubregions)
    {
        return new IdentifiedRegion(IdentifiedRegion.countryAndSubregions, countryAndSubregions);
    }


    public static IdentifiedRegion getInstance(Object o)
    {
        if (o instanceof IdentifiedRegion)
        {
            return (IdentifiedRegion)o;
        }
        if (o != null)
        {
            return new IdentifiedRegion(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getIdentifiedRegion()
    {
        return identifiedRegion;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, identifiedRegion);
    }
}
