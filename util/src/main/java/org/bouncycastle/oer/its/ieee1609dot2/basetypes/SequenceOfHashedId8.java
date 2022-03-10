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


public class SequenceOfHashedId8
    extends ASN1Object
{
    private final List<HashedId8> hashedId8s;

    public SequenceOfHashedId8(List<HashedId8> hashedId8s)
    {
        this.hashedId8s = Collections.unmodifiableList(hashedId8s);
    }

    private SequenceOfHashedId8(ASN1Sequence sequence)
    {
        List<HashedId8> items = new ArrayList<HashedId8>();
        for (Iterator<ASN1Encodable> it = sequence.iterator(); it.hasNext(); )
        {
            items.add(HashedId8.getInstance(it.next()));
        }
        this.hashedId8s = Collections.unmodifiableList(items);
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static SequenceOfHashedId8 getInstance(Object o)
    {
        if (o instanceof SequenceOfHashedId8)
        {
            return (SequenceOfHashedId8)o;
        }
        if (o != null)
        {
            return new SequenceOfHashedId8(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public List<HashedId8> getHashedId8s()
    {
        return hashedId8s;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(hashedId8s.toArray(new ASN1Encodable[0]));
    }

    public static class Builder
    {
        private final List<HashedId8> items = new ArrayList<HashedId8>();

        public Builder addHashId8(HashedId8... items)
        {
            this.items.addAll(Arrays.asList(items));
            return this;
        }

        public SequenceOfHashedId8 build()
        {
            return new SequenceOfHashedId8(items);
        }
    }

}
