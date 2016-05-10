package com.github.gv2011.bcasn.pqc.asn1;

import java.math.BigInteger;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1ObjectIdentifier;
import com.github.gv2011.bcasn.asn1.ASN1OctetString;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DEROctetString;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.pqc.math.linearalgebra.GF2Matrix;

public class McElieceCCA2PublicKey
    extends ASN1Object
{
    private ASN1ObjectIdentifier oid;
    private int n;
    private int t;

    private byte[] matrixG;

    public McElieceCCA2PublicKey(ASN1ObjectIdentifier oid, int n, int t, GF2Matrix g)
    {
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.matrixG = g.getEncoded();
    }

    private McElieceCCA2PublicKey(ASN1Sequence seq)
    {
        oid = ((ASN1ObjectIdentifier)seq.getObjectAt(0));
        BigInteger bigN = ((ASN1Integer)seq.getObjectAt(1)).getValue();
        n = bigN.intValue();

        BigInteger bigT = ((ASN1Integer)seq.getObjectAt(2)).getValue();
        t = bigT.intValue();

        matrixG = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();
    }

    public ASN1ObjectIdentifier getOID()
    {
        return oid;
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
        return new GF2Matrix(matrixG);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        // encode <oidString>
        v.add(oid);

        // encode <n>
        v.add(new ASN1Integer(n));

        // encode <t>
        v.add(new ASN1Integer(t));

        // encode <matrixG>
        v.add(new DEROctetString(matrixG));

        return new DERSequence(v);
    }

    public static McElieceCCA2PublicKey getInstance(Object o)
    {
        if (o instanceof McElieceCCA2PublicKey)
        {
            return (McElieceCCA2PublicKey)o;
        }
        else if (o != null)
        {
            return new McElieceCCA2PublicKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }
}
