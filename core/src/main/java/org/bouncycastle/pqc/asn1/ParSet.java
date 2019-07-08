package org.bouncycastle.pqc.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/**
 * <pre>
 *  ParSet              ::= SEQUENCE {
 *      T               INTEGER
 *      h               SEQUENCE OF INTEGER
 *      w               SEQUENCE OF INTEGER
 *      K               SEQUENCE OF INTEGER
 *  }
 * </pre>
 */
public class ParSet
    extends ASN1Object
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private int   t;
    private int[] h;
    private int[] w;
    private int[] k;

    private static int checkBigIntegerInIntRangeAndPositive(ASN1Encodable e)
    {
        ASN1Integer i = (ASN1Integer)e;
        int value = i.intValueExact();
        if (value <= 0)
        {
            throw new IllegalArgumentException("BigInteger not in Range: " + value);
        }
        return value;
    }

    private ParSet(ASN1Sequence seq)
    {
        if (seq.size() != 4)
        {
            throw new IllegalArgumentException("sie of seqOfParams = " + seq.size());
        }

        t = checkBigIntegerInIntRangeAndPositive(seq.getObjectAt(0));

        ASN1Sequence seqOfPSh = (ASN1Sequence)seq.getObjectAt(1);
        ASN1Sequence seqOfPSw = (ASN1Sequence)seq.getObjectAt(2);
        ASN1Sequence seqOfPSK = (ASN1Sequence)seq.getObjectAt(3);

        if ((seqOfPSh.size() != t) ||
            (seqOfPSw.size() != t) ||
            (seqOfPSK.size() != t))
        {
            throw new IllegalArgumentException("invalid size of sequences");
        }

        h = new int[seqOfPSh.size()];
        w = new int[seqOfPSw.size()];
        k = new int[seqOfPSK.size()];

        for (int i = 0; i < t; i++)
        {
            h[i] = checkBigIntegerInIntRangeAndPositive(seqOfPSh.getObjectAt(i));
            w[i] = checkBigIntegerInIntRangeAndPositive(seqOfPSw.getObjectAt(i));
            k[i] = checkBigIntegerInIntRangeAndPositive(seqOfPSK.getObjectAt(i));
        }
    }

    public ParSet(int t, int[] h, int[] w, int[] k)
    {
        this.t = t;
        this.h = h;
        this.w = w;
        this.k = k;
    }

    public static ParSet getInstance(Object o)
    {
        if (o instanceof ParSet)
        {
            return (ParSet)o;
        }
        else if (o != null)
        {
            return new ParSet(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getT()
    {
        return t;
    }

    public int[] getH()
    {
        return Arrays.clone(h);
    }

    public int[] getW()
    {
        return Arrays.clone(w);
    }

    public int[] getK()
    {
        return Arrays.clone(k);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector seqOfPSh = new ASN1EncodableVector();
        ASN1EncodableVector seqOfPSw = new ASN1EncodableVector();
        ASN1EncodableVector seqOfPSK = new ASN1EncodableVector();

        for (int i = 0; i < h.length; i++)
        {
            seqOfPSh.add(new ASN1Integer(h[i]));
            seqOfPSw.add(new ASN1Integer(w[i]));
            seqOfPSK.add(new ASN1Integer(k[i]));
        }

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(t));
        v.add(new DERSequence(seqOfPSh));
        v.add(new DERSequence(seqOfPSw));
        v.add(new DERSequence(seqOfPSK));

        return new DERSequence(v);
    }
}
