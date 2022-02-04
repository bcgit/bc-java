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
public class SequenceOfRegionAndSubregions
    extends ASN1Object
{
    private final List<RegionAndSubregions> regionAndSubregions;


    public SequenceOfRegionAndSubregions(List<RegionAndSubregions> items)
    {
        regionAndSubregions = Collections.unmodifiableList(items);
    }

    private SequenceOfRegionAndSubregions(ASN1Sequence s)
    {
        ArrayList<RegionAndSubregions> items = new ArrayList<RegionAndSubregions>();
        for (Iterator<ASN1Encodable> it = s.iterator(); it.hasNext(); )
        {
            items.add(RegionAndSubregions.getInstance(it.next()));
        }
        regionAndSubregions = Collections.unmodifiableList(items);
    }

    public static SequenceOfRegionAndSubregions getInstance(Object o)
    {
        if (o instanceof SequenceOfRegionAndSubregions)
        {
            return (SequenceOfRegionAndSubregions)o;
        }

        if (o != null)
        {
            return new SequenceOfRegionAndSubregions(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public List<RegionAndSubregions> getRegionAndSubregions()
    {
        return regionAndSubregions;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return ItsUtils.toSequence(regionAndSubregions);
    }
}
