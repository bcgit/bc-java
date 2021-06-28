package org.bouncycastle.oer.its;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class SequenceOfIdentifiedRegion
    extends ASN1Object
{

    public static SequenceOfIdentifiedRegion getInstance(Object o)
    {
        if (o instanceof SequenceOfIdentifiedRegion)
        {
            return (SequenceOfIdentifiedRegion)o;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(o);
        List<IdentifiedRegion> regions = new ArrayList<>();
        for (Iterator<ASN1Encodable> it = seq.iterator(); it.hasNext(); )
        {
            regions.add(IdentifiedRegion.getInstance(it.next()));
        }

        return new SequenceOfIdentifiedRegion(regions);
    }


    public SequenceOfIdentifiedRegion(List<IdentifiedRegion> identifiedRegions)
    {
        this.identifiedRegions = Collections.unmodifiableList(identifiedRegions);
    }

    private final List<IdentifiedRegion> identifiedRegions;

    public List<IdentifiedRegion> getIdentifiedRegions()
    {
        return identifiedRegions;
    }


    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(identifiedRegions.toArray(new ASN1Encodable[0]));
    }
}
