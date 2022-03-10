package org.bouncycastle.oer.its.etsi102941;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;


public class SequenceOfCrlEntry
    extends ASN1Object
{
    private final List<CrlEntry> crlEntries;

    public SequenceOfCrlEntry(List<CrlEntry> crlEntries)
    {
        this.crlEntries = Collections.unmodifiableList(crlEntries);
    }

    private SequenceOfCrlEntry(ASN1Sequence sequence)
    {
        List<CrlEntry> items = new ArrayList<CrlEntry>();
        for (Iterator<ASN1Encodable> it = sequence.iterator(); it.hasNext(); )
        {
            items.add(CrlEntry.getInstance(it.next()));
        }
        this.crlEntries = Collections.unmodifiableList(items);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static SequenceOfCrlEntry getInstance(Object o)
    {
        if (o instanceof SequenceOfCrlEntry)
        {
            return (SequenceOfCrlEntry)o;
        }
        if (o != null)
        {
            return new SequenceOfCrlEntry(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public List<CrlEntry> getCrlEntries()
    {
        return crlEntries;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(crlEntries.toArray(new ASN1Encodable[0]));
    }

    public static class Builder
    {
        private final List<CrlEntry> items = new ArrayList<CrlEntry>();

        public Builder addCrlEntry(CrlEntry... items)
        {
            this.items.addAll(Arrays.asList(items));
            return this;
        }

        public SequenceOfCrlEntry build()
        {
            return new SequenceOfCrlEntry(items);
        }
    }

}
