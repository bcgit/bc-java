package org.bouncycastle.oer.its;

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

    public static IdentifiedRegion getInstance(Object o)
    {
        if (o instanceof IdentifiedRegion)
        {
            return (IdentifiedRegion)o;
        }
        else
        {
            ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(o);

            int choice = asn1TaggedObject.getTagNo();

            o = asn1TaggedObject.getObject();
            switch (choice)
            {
            case countryOnly:
                return new IdentifiedRegion(choice, CountryOnly.getInstance(o));
            case countryAndRegions:
                return new IdentifiedRegion(choice, CountryAndRegions.getInstance(o));
            case countAndSubregions:
                return new IdentifiedRegion(choice, RegionAndSubregions.getInstance(o));
            case extension:
                return new IdentifiedRegion(choice, DEROctetString.getInstance(o));
            default:
                throw new IllegalArgumentException("unknown choice " + choice);
            }


        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, region).toASN1Primitive();
    }
}
