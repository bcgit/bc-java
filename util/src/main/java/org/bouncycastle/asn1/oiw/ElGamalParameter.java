package org.bouncycastle.asn1.oiw;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class ElGamalParameter
    extends ASN1Object
{
    ASN1Integer      p, g;

    public ElGamalParameter(
        BigInteger  p,
        BigInteger  g)
    {
        this.p = new ASN1Integer(p);
        this.g = new ASN1Integer(g);
    }

    private ElGamalParameter(
        ASN1Sequence  seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        p = ASN1Integer.getInstance(seq.getObjectAt(0));
        g = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public static ElGamalParameter getInstance(Object o)
    {
        if (o instanceof ElGamalParameter)
        {
            return (ElGamalParameter)o;
        }
        else if (o != null)
        {
            return new ElGamalParameter(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public BigInteger getP()
    {
        return p.getPositiveValue();
    }

    public BigInteger getG()
    {
        return g.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(p, g);
    }
}
