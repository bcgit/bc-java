package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.oer.its.ItsUtils;

/**
 * <pre>
 *     SequenceOfRectangularRegion ::= SEQUENCE OF RectangularRegion
 * </pre>
 */
public class SequenceOfRectangularRegion
    extends ASN1Object
{
    private final List<RectangularRegion> rectangularRegions;


    public SequenceOfRectangularRegion(List<RectangularRegion> items)
    {
        rectangularRegions = Collections.unmodifiableList(items);
    }


    public static SequenceOfRectangularRegion getInstance(Object o)
    {
        if (o instanceof SequenceOfRectangularRegion)
        {
            return (SequenceOfRectangularRegion)o;
        }

        return new SequenceOfRectangularRegion(ItsUtils.fillList(RectangularRegion.class, ASN1Sequence.getInstance(o)));
    }


    public List<RectangularRegion> getRectangularRegions()
    {
        return rectangularRegions;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(rectangularRegions);
    }
}
