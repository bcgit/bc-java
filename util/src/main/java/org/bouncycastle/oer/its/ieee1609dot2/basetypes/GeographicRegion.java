package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
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

    private final int choice;
    private final ASN1Encodable geographicRegion;

    public GeographicRegion(int choice, ASN1Encodable region)
    {
        this.choice = choice;
        this.geographicRegion = region;
    }


    private GeographicRegion(ASN1TaggedObject taggedObject)
    {
        choice = taggedObject.getTagNo();

        switch (choice)
        {
        case circularRegion:
            geographicRegion = CircularRegion.getInstance(taggedObject.getExplicitBaseObject());
            break;
        case rectangularRegion:
            geographicRegion = SequenceOfRectangularRegion.getInstance(taggedObject.getExplicitBaseObject());
            break;
        case polygonalRegion:
            geographicRegion = PolygonalRegion.getInstance(taggedObject.getExplicitBaseObject());
            break;
        case identifiedRegion:
            geographicRegion = SequenceOfIdentifiedRegion.getInstance(taggedObject.getExplicitBaseObject());
            break;
        default:
            throw new IllegalArgumentException("invalid choice value " + choice);
        }
    }

    public static GeographicRegion circularRegion(CircularRegion region)
    {
        return new GeographicRegion(circularRegion, region);
    }

    public static GeographicRegion rectangularRegion(SequenceOfRectangularRegion region)
    {
        return new GeographicRegion(rectangularRegion, region);
    }

    public static GeographicRegion polygonalRegion(PolygonalRegion region)
    {
        return new GeographicRegion(polygonalRegion, region);
    }

    public static GeographicRegion identifiedRegion(SequenceOfIdentifiedRegion region)
    {
        return new GeographicRegion(identifiedRegion, region);
    }


    public static GeographicRegion getInstance(Object o)
    {
        if (o instanceof GeographicRegion)
        {
            return (GeographicRegion)o;
        }
        if (o != null)
        {
            return new GeographicRegion(ASN1TaggedObject.getInstance(o, BERTags.CONTEXT_SPECIFIC));
        }

        return null;
    }

    public int getChoice()
    {
        return choice;
    }

    public ASN1Encodable getGeographicRegion()
    {
        return geographicRegion;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, geographicRegion);
    }
}
