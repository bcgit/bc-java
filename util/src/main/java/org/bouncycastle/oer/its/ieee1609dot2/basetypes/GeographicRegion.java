package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * <pre>
 *     GeographicRegion ::= CHOICE {
 *         circularRegion CircularRegion,
 *         rectangularRegion SequenceOfRectangularRegion,
 *         polygonalRegion PolygonalRegion,
 *         identifiedRegion SequenceOfIdentifiedRegion,
 *         ...
 *     }
 * </pre>
 */
public class GeographicRegion
    extends ASN1Object
    implements ASN1Choice
{

    public static final int circularRegion = 0;
    public static final int rectangularRegion = 1;
    public static final int polygonalRegion = 2;
    public static final int identifiedRegion = 3;
    public static final int extension = 4;

    private final int choice;
    private final ASN1Encodable region;

    public GeographicRegion(int choice, ASN1Encodable region)
    {
        this.choice = choice;
        this.region = region;
    }


    private GeographicRegion(ASN1TaggedObject taggedObject)
    {
        choice = taggedObject.getTagNo();

        switch (choice)
        {
        case circularRegion:
            region = CircularRegion.getInstance(taggedObject.getObject());
            break;
        case rectangularRegion:
            region = SequenceOfRectangularRegion.getInstance(taggedObject.getObject());
            break;
        case polygonalRegion:
            region = PolygonalRegion.getInstance(taggedObject.getObject());
            break;
        case identifiedRegion:
            region = SequenceOfIdentifiedRegion.getInstance(taggedObject.getObject());
            break;
        case extension:
            region = DEROctetString.getInstance(taggedObject.getObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }


    }

    public static GeographicRegion getInstance(Object o)
    {
        if (o instanceof GeographicRegion)
        {
            return (GeographicRegion)o;
        }
        if (o != null)
        {
            return new GeographicRegion(ASN1TaggedObject.getInstance(o));
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
