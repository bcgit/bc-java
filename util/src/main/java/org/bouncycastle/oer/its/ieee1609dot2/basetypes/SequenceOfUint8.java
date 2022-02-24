package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * SequenceOfUint8  ::= SEQUENCE OF Uint8
 */
public class SequenceOfUint8
    extends ASN1Object
{
    private final List<UINT8> uint8s;

    public SequenceOfUint8(List<UINT8> values)
    {
        this.uint8s = Collections.unmodifiableList(values);
    }

    private SequenceOfUint8(ASN1Sequence sequence)
    {
        List<UINT8> items = new ArrayList<UINT8>();
        for (Iterator<ASN1Encodable> it = sequence.iterator(); it.hasNext(); )
        {
            items.add(UINT8.getInstance(it.next()));
        }
        this.uint8s = Collections.unmodifiableList(items);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static SequenceOfUint8 getInstance(Object o)
    {
        if (o instanceof SequenceOfUint8)
        {
            return (SequenceOfUint8)o;
        }
        if (o != null)
        {
            return new SequenceOfUint8(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public List<UINT8> getUint8s()
    {
        return uint8s;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (UINT8 uint8 : uint8s)
        {
            vector.add(uint8.toASN1Primitive());
        }
        return new DERSequence(vector);
    }

    public static class Builder
    {
        private final List<UINT8> items = new ArrayList<UINT8>();

        public Builder addHashId3(UINT8... items)
        {
            this.items.addAll(Arrays.asList(items));
            return this;
        }

        public SequenceOfUint8 build()
        {
            return new SequenceOfUint8(items);
        }
    }


}
