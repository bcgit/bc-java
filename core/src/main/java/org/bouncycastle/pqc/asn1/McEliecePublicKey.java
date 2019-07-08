package org.bouncycastle.pqc.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

public class McEliecePublicKey
    extends ASN1Object
{
    private final int n;
    private final int t;
    private final GF2Matrix g;

    public McEliecePublicKey(int n, int t, GF2Matrix g)
    {
        this.n = n;
        this.t = t;
        this.g = new GF2Matrix(g);
    }

    private McEliecePublicKey(ASN1Sequence seq)
    {
        n = ((ASN1Integer)seq.getObjectAt(0)).intValueExact();

        t = ((ASN1Integer)seq.getObjectAt(1)).intValueExact();

        g = new GF2Matrix(((ASN1OctetString)seq.getObjectAt(2)).getOctets());
    }

    public int getN()
    {
        return n;
    }

    public int getT()
    {
        return t;
    }

    public GF2Matrix getG()
    {
        return new GF2Matrix(g);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        // encode <n>
        v.add(new ASN1Integer(n));

        // encode <t>
        v.add(new ASN1Integer(t));

        // encode <matrixG>
        v.add(new DEROctetString(g.getEncoded()));

        return new DERSequence(v);
    }

    public static McEliecePublicKey getInstance(Object o)
    {
        if (o instanceof McEliecePublicKey)
        {
            return (McEliecePublicKey)o;
        }
        else if (o != null)
        {
            return new McEliecePublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
