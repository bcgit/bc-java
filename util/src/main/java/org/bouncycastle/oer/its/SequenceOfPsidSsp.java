package org.bouncycastle.oer.its;

import java.util.ArrayList;
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

/**
 * SequenceOfPsidSsp ::= SEQUENCE OF PsidSsp
 */
public class SequenceOfPsidSsp
    extends ASN1Object
{
    private final List<PsidSsp> items;

    public SequenceOfPsidSsp(List<PsidSsp> items)
    {
        this.items = Collections.unmodifiableList(items);
    }

    public static SequenceOfPsidSsp getInstance(Object o)
    {
        if (o instanceof SequenceOfPsidSsp)
        {
            return (SequenceOfPsidSsp)o;
        }
        ASN1Sequence sequence = ASN1Sequence.getInstance(o);
        Enumeration e = sequence.getObjects();
        ArrayList<PsidSsp> accumulator = new ArrayList<PsidSsp>();
        while (e.hasMoreElements())
        {
            accumulator.add(PsidSsp.getInstance(e.nextElement()));
        }
        return new Builder().setItems(accumulator).createSequenceOfPsidSsp();
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public List<PsidSsp> getItems()
    {
        return items;
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

        private List<PsidSsp> items = new ArrayList<PsidSsp>();

        public Builder setItems(List<PsidSsp> items)
        {
            this.items = items;
            return this;
        }

        public Builder setItem(PsidSsp... items)
        {
            for (int i = 0; i != items.length; i++)
            {
                PsidSsp item = items[i];
                this.items.add(item);
            }
            return this;
        }

        public SequenceOfPsidSsp createSequenceOfPsidSsp()
        {
            return new SequenceOfPsidSsp(items);
        }
    }
}
