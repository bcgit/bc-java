package org.bouncycastle.asn1.x9;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * ASN.1 def for Elliptic-Curve ECParameters structure. See
 * X9.62, for further details.
 */
public class X9ECParameters
    extends ASN1Object
    implements X9ObjectIdentifiers
{
    private final X9FieldID    fieldID;
    private final ECDomainParameters dp;

    private X9ECParameters( final ASN1Sequence seq )
    {
        if (!(seq.getObjectAt(0) instanceof ASN1Integer)
           || !((ASN1Integer)seq.getObjectAt(0)).getValue().equals(BigInteger.ONE))
        {
            throw new IllegalArgumentException("bad version in X9ECParameters");
        }

        final X9Curve x9c = new X9Curve(
                        X9FieldID.getInstance(seq.getObjectAt(1)),
                        ASN1Sequence.getInstance(seq.getObjectAt(2)));

        final ECCurve curve = x9c.getCurve();
        final ECPoint g;

        final Object p = seq.getObjectAt(3);
        if (p instanceof X9ECPoint) {
            g = ((X9ECPoint)p).getPoint();
        } else {
            g = new X9ECPoint(curve, (ASN1OctetString)p).getPoint();
        }

        final BigInteger n = ((ASN1Integer)seq.getObjectAt(4)).getValue();
        final byte[] seed = x9c.getSeed();

        final BigInteger h;
        if (seq.size() == 6) {
            h = ((ASN1Integer)seq.getObjectAt(5)).getValue();
        } else {
            h = null;
        }

        this.dp = new ECDomainParameters(curve, g, n, h, seed);
        this.fieldID = determineFieldID(curve);
    }

    private static X9FieldID determineFieldID( final ECCurve curve ) {
        if (curve instanceof ECCurve.Fp) {
            return new X9FieldID(((ECCurve.Fp)curve).getQ());
        } else if (curve instanceof ECCurve.F2m) {
            final ECCurve.F2m curveF2m = (ECCurve.F2m)curve;
            return new X9FieldID(curveF2m.getM(), curveF2m.getK1(),
                                 curveF2m.getK2(), curveF2m.getK3());
        }
        return null;
    }

    public static X9ECParameters getInstance(Object obj)
    {
        if (obj instanceof X9ECParameters)
        {
            return (X9ECParameters)obj;
        }

        if (obj != null)
        {
            return new X9ECParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public X9ECParameters( final ECDomainParameters dp )
    {
        this.dp = dp;
        this.fieldID = determineFieldID(dp.getCurve());
    }

    public X9ECParameters(
        ECCurve     curve,
        ECPoint     g,
        BigInteger  n)
    {
        this(curve, g, n, BigInteger.ONE, null);
    }

    public X9ECParameters(
        ECCurve     curve,
        ECPoint     g,
        BigInteger  n,
        BigInteger  h)
    {
        this(curve, g, n, h, null);
    }

    public X9ECParameters(
        ECCurve     curve,
        ECPoint     g,
        BigInteger  n,
        BigInteger  h,
        byte[]      seed)
    {
        this.dp = new ECDomainParameters(curve, g, n, h, seed);
        this.fieldID = determineFieldID(curve);
    }

    public ECDomainParameters getECDomainParameters()
    {
        return this.dp;
    }

    public ECCurve getCurve()
    {
        return this.dp.getCurve();
    }

    public ECPoint getG()
    {
        return this.dp.getG();
    }

    public BigInteger getN()
    {
        return this.dp.getN();
    }

    public BigInteger getH()
    {
        BigInteger h = this.dp.getH();
        if (h != null) return h;

        return BigInteger.ONE; // TODO - this should be calculated, it will cause issues with custom curves.
    }

    public byte[] getSeed()
    {
        return this.dp.getSeed();
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  ECParameters ::= SEQUENCE {
     *      version         INTEGER { ecpVer1(1) } (ecpVer1),
     *      fieldID         FieldID {{FieldTypes}},
     *      curve           X9Curve,
     *      base            X9ECPoint,
     *      order           INTEGER,
     *      cofactor        INTEGER OPTIONAL
     *  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(1));
        v.add(fieldID);
        v.add(new X9Curve(this.dp.getCurve(), this.dp.getSeed()));
        v.add(new X9ECPoint(this.dp.getG()));
        v.add(new ASN1Integer(this.dp.getN()));

        BigInteger h = this.dp.getH();
        if (h != null)
        {
            v.add(new ASN1Integer(h));
        }

        return new DERSequence(v);
    }
}
