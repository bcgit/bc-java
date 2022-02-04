package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

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

/**
 * SequenceOfUint16 ::= SEQUENCE OF Uint16
 */
public class SequenceOfUint16
    extends ASN1Object
{
    private final List<UINT16> uint16s;

    public SequenceOfUint16(List<UINT16> uint16)
    {
        this.uint16s = Collections.unmodifiableList(uint16);
    }

    private SequenceOfUint16(ASN1Sequence sequence)
    {
        List<UINT16> items = new ArrayList<UINT16>();
        for (Iterator<ASN1Encodable> it = sequence.iterator(); it.hasNext(); )
        {
            items.add(UINT16.getInstance(it.next()));
        }
        this.uint16s = Collections.unmodifiableList(items);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static SequenceOfUint16 getInstance(Object o)
    {
        if (o instanceof SequenceOfUint16)
        {
            return (SequenceOfUint16)o;
        }
        if (o != null)
        {
            return new SequenceOfUint16(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public List<UINT16> getUint16s()
    {
        return uint16s;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(uint16s.toArray(new ASN1Encodable[0]));
    }

    public static class Builder
    {
        private final List<UINT16> items = new ArrayList<UINT16>();

        public Builder addHashId3(UINT16... items)
        {
            this.items.addAll(Arrays.asList(items));
            return this;
        }

        public SequenceOfUint16 build()
        {
            return new SequenceOfUint16(items);
        }
    }


}
