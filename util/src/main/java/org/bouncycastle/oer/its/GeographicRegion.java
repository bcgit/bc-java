package org.bouncycastle.oer.its;

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

    public static GeographicRegion getInstance(Object o)
    {
        if (o instanceof GeographicRegion)
        {
            return (GeographicRegion)o;
        }
        else
        {
            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(o);

            int choice = taggedObject.getTagNo();

            switch (choice)
            {
            case circularRegion:
                return new GeographicRegion(choice, CircularRegion.getInstance(taggedObject.getObject()));
            case rectangularRegion:
                return new GeographicRegion(choice, SequenceOfRectangularRegion.getInstance(taggedObject.getObject()));
            case polygonalRegion:
                return new GeographicRegion(choice, PolygonalRegion.getInstance(taggedObject.getObject()));
            case identifiedRegion:
                return new GeographicRegion(choice, SequenceOfIdentifiedRegion.getInstance(taggedObject.getObject()));
            case extension:
                return new GeographicRegion(choice, DEROctetString.getInstance(taggedObject.getObject()));
            default:
                throw new IllegalStateException("unknown region choice " + choice);
            }

        }

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
