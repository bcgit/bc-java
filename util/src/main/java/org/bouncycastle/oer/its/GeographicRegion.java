package org.bouncycastle.oer.its;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
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

    private int choice;
    private RegionInterface region;

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

            o = taggedObject.getObject();
            switch (choice)
            {
            case circularRegion:
                return new GeographicRegion(choice, CircularRegion.getInstance(o));
            case rectangularRegion:
                return new GeographicRegion(choice, RectangularRegion.getInstance(o));
            case polygonalRegion:
                return new GeographicRegion(choice, PolygonalRegion.getInstance(o));
            case identifiedRegion:
                return new GeographicRegion(choice, IdentifiedRegion.getInstance(o));
            default:
                throw new IllegalStateException("unknown region choice " + choice);
            }

        }

    }

    public GeographicRegion(int choice, RegionInterface region)
    {
        this.choice = choice;
        this.region = region;
    }

    public int getChoice()
    {
        return choice;
    }

    public void setChoice(int choice)
    {
        this.choice = choice;
    }

    public RegionInterface getRegion()
    {
        return region;
    }

    public void setRegion(RegionInterface region)
    {
        this.region = region;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(choice, region);
    }
}
