package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class GenericKemTransParameters
    extends ASN1Object
{
    private final AlgorithmIdentifier kem;
    private final AlgorithmIdentifier kdf;
    private final AlgorithmIdentifier wrap;

    public GenericKemTransParameters(AlgorithmIdentifier kem, AlgorithmIdentifier kdf, AlgorithmIdentifier wrap)
    {
        if (kem == null)
        {
            throw new NullPointerException("kem cannot be null");
        }
        if (wrap == null)
        {
            throw new NullPointerException("wrap cannot be null");
        }
        this.kem = kem;
        this.kdf = kdf;
        this.wrap = wrap;
    }

    public static GenericKemTransParameters getInstance(Object o)
    {
        if (o instanceof GenericKemTransParameters)
        {
            return (GenericKemTransParameters)o;
        }
        else if (o != null)
        {
            return new GenericKemTransParameters(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private GenericKemTransParameters(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("sequence must consist of 3 elements");
        }

        kem = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        if (seq.getObjectAt(1) instanceof ASN1Null)
        {
            kdf = null;
        }
        else
        {
            kdf = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        }
        wrap = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
    }

    public GenericKemTransParameters(AlgorithmIdentifier kem, AlgorithmIdentifier wrap)
    {
        this(kem, null, wrap);
    }

    public AlgorithmIdentifier getKem()
    {
        return kem;
    }

    public AlgorithmIdentifier getKdf()
    {
        return kdf;
    }

    public AlgorithmIdentifier getWrap()
    {
        return wrap;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(kem);

        if (kdf != null)
        {
            v.add(kdf);
        }
        else
        {
            v.add(DERNull.INSTANCE);
        }

        v.add(wrap);
        
        return new DERSequence(v);
    }
}
