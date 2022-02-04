package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
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

    private SequenceOfRectangularRegion(ASN1Sequence s)
    {
        ArrayList<RectangularRegion> l = new ArrayList<RectangularRegion>();
        for (Iterator<ASN1Encodable> it = s.iterator(); it.hasNext(); )
        {
            l.add(RectangularRegion.getInstance(it.next()));
        }
        rectangularRegions = Collections.unmodifiableList(l);
    }


    public static SequenceOfRectangularRegion getInstance(Object o)
    {
        if (o instanceof SequenceOfRectangularRegion)
        {
            return (SequenceOfRectangularRegion)o;
        }

        if (o != null)
        {
            return new SequenceOfRectangularRegion(ASN1Sequence.getInstance(o));
        }

        return null;
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
