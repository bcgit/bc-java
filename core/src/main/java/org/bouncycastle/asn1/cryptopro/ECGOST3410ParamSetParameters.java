package org.bouncycastle.asn1.cryptopro;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class ECGOST3410ParamSetParameters
    extends ASN1Object
{
    ASN1Integer      p, q, a, b, x, y;

    public static ECGOST3410ParamSetParameters getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ECGOST3410ParamSetParameters getInstance(
        Object obj)
    {
        if(obj == null || obj instanceof ECGOST3410ParamSetParameters)
        {
            return (ECGOST3410ParamSetParameters)obj;
        }

        if(obj instanceof ASN1Sequence)
        {
            return new ECGOST3410ParamSetParameters((ASN1Sequence)obj);
        }

        throw new IllegalArgumentException("Invalid GOST3410Parameter: " + obj.getClass().getName());
    }

    public ECGOST3410ParamSetParameters(
        BigInteger a,
        BigInteger b,
        BigInteger p,
        BigInteger q,
        int        x,
        BigInteger y)
    {
        this.a = new ASN1Integer(a);
        this.b = new ASN1Integer(b);
        this.p = new ASN1Integer(p);
        this.q = new ASN1Integer(q);
        this.x = ASN1Integer.valueOf(x);
        this.y = new ASN1Integer(y);
    }

    public ECGOST3410ParamSetParameters(
        ASN1Sequence  seq)
    {
        if (seq.size() != 6)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        a = ASN1Integer.getInstance(seq.getObjectAt(0));
        b = ASN1Integer.getInstance(seq.getObjectAt(1));
        p = ASN1Integer.getInstance(seq.getObjectAt(2));
        q = ASN1Integer.getInstance(seq.getObjectAt(3));
        x = ASN1Integer.getInstance(seq.getObjectAt(4));
        y = ASN1Integer.getInstance(seq.getObjectAt(5));
    }
    
    public BigInteger getP()
    {
        return p.getPositiveValue();
    }

    public BigInteger getQ()
    {
        return q.getPositiveValue();
    }

    public BigInteger getA()
    {
        return a.getPositiveValue();
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(6);

        v.add(a);
        v.add(b);
        v.add(p);
        v.add(q);
        v.add(x);
        v.add(y);

        return new DERSequence(v);
    }
}
