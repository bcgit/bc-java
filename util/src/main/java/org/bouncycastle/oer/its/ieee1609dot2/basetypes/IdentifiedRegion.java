package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
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
    public static final int countAndSubregions = 2;
    public static final int extension = 3;

    private final int choice;
    private final ASN1Encodable region;

    public IdentifiedRegion(int choice, ASN1Encodable region)
    {
        this.choice = choice;
        this.region = region;
    }

    private IdentifiedRegion(ASN1TaggedObject ato)
    {
        this.choice = ato.getTagNo();

        switch (choice)
        {
        case countryOnly:
            region = CountryOnly.getInstance(ato.getObject());
            break;
        case countryAndRegions:
            region = CountryAndRegions.getInstance(ato.getObject());
            break;
        case countAndSubregions:
            region = CountryAndSubregions.getInstance(ato.getObject());
            break;
        case extension:
            region = DEROctetString.getInstance(ato.getObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }


    public static IdentifiedRegion getInstance(Object o)
    {
        if (o instanceof IdentifiedRegion)
        {
            return (IdentifiedRegion)o;
        }
        if (o != null)
        {
            return new IdentifiedRegion(ASN1TaggedObject.getInstance(o));
        }

        return null;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getRegion()
    {
        return region;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, region);
    }
}
