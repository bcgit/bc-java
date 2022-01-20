package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class SequenceOfPsidSspRange
    extends ASN1Object
{
    private final List<PsidSspRange> items;

    public SequenceOfPsidSspRange(List<PsidSspRange> items)
    {
        this.items = Collections.unmodifiableList(items);
    }

    public static SequenceOfPsidSspRange getInstance(Object o)
    {
        if (o instanceof SequenceOfPsidSspRange)
        {
            return (SequenceOfPsidSspRange)o;
        }
        ASN1Sequence sequence = ASN1Sequence.getInstance(o);
        Enumeration e = sequence.getObjects();
        ArrayList<PsidSspRange> accumulator = new ArrayList<PsidSspRange>();
        while (e.hasMoreElements())
        {
            accumulator.add(PsidSspRange.getInstance(e.nextElement()));
        }
        return new SequenceOfPsidSspRange(accumulator);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector avec = new ASN1EncodableVector();
        for (Iterator it = items.iterator(); it.hasNext(); )
        {
            avec.add((ASN1Encodable)it.next());
        }
        return new DERSequence(avec);
    }

    public static class Builder
    {
        private final ArrayList<PsidSspRange> psidSspRanges = new ArrayList<PsidSspRange>();

        public Builder add(PsidSspRange... ranges)
        {
            psidSspRanges.addAll(Arrays.asList(ranges));
            return this;
        }


        public SequenceOfPsidSspRange build()
        {
            return new SequenceOfPsidSspRange(psidSspRanges);
        }

    }
}
