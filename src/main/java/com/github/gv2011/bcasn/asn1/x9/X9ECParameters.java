package com.github.gv2011.bcasn.asn1.x9;

import java.math.BigInteger;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Integer;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1OctetString;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.math.ec.ECAlgorithms;
import com.github.gv2011.bcasn.math.ec.ECCurve;
import com.github.gv2011.bcasn.math.ec.ECPoint;
import com.github.gv2011.bcasn.math.field.PolynomialExtensionField;

/**
 * ASN.1 def for Elliptic-Curve ECParameters structure. See
 * X9.62, for further details.
 */
public class X9ECParameters
    extends ASN1Object
    implements X9ObjectIdentifiers
{
    private static final BigInteger   ONE = BigInteger.valueOf(1);

    private X9FieldID           fieldID;
    private ECCurve             curve;
    private X9ECPoint           g;
    private BigInteger          n;
    private BigInteger          h;
    private byte[]              seed;

    private X9ECParameters(
        ASN1Sequence  seq)
    {
        if (!(seq.getObjectAt(0) instanceof ASN1Integer)
           || !((ASN1Integer)seq.getObjectAt(0)).getValue().equals(ONE))
        {
            throw new IllegalArgumentException("bad version in X9ECParameters");
        }

        X9Curve     x9c = new X9Curve(
                        X9FieldID.getInstance(seq.getObjectAt(1)),
                        ASN1Sequence.getInstance(seq.getObjectAt(2)));

        this.curve = x9c.getCurve();
        Object p = seq.getObjectAt(3);

        if (p instanceof X9ECPoint)
        {
            this.g = ((X9ECPoint)p);
        }
        else
        {
            this.g = new X9ECPoint(curve, (ASN1OctetString)p);
        }

        this.n = ((ASN1Integer)seq.getObjectAt(4)).getValue();
        this.seed = x9c.getSeed();

        if (seq.size() == 6)
        {
            this.h = ((ASN1Integer)seq.getObjectAt(5)).getValue();
        }
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

    public X9ECParameters(
        ECCurve     curve,
        ECPoint     g,
        BigInteger  n)
    {
        this(curve, g, n, null, null);
    }

    public X9ECParameters(
        ECCurve     curve,
        X9ECPoint     g,
        BigInteger  n,
        BigInteger  h)
    {
        this(curve, g, n, h, null);
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
        this(curve, new X9ECPoint(g), n, h, seed);
    }

    public X9ECParameters(
        ECCurve     curve,
        X9ECPoint   g,
        BigInteger  n,
        BigInteger  h,
        byte[]      seed)
    {
        this.curve = curve;
        this.g = g;
        this.n = n;
        this.h = h;
        this.seed = seed;

        if (ECAlgorithms.isFpCurve(curve))
        {
            this.fieldID = new X9FieldID(curve.getField().getCharacteristic());
        }
        else if (ECAlgorithms.isF2mCurve(curve))
        {
            PolynomialExtensionField field = (PolynomialExtensionField)curve.getField();
            int[] exponents = field.getMinimalPolynomial().getExponentsPresent();
            if (exponents.length == 3)
            {
                this.fieldID = new X9FieldID(exponents[2], exponents[1]);
            }
            else if (exponents.length == 5)
            {
                this.fieldID = new X9FieldID(exponents[4], exponents[1], exponents[2], exponents[3]);
            }
            else
            {
                throw new IllegalArgumentException("Only trinomial and pentomial curves are supported");
            }
        }
        else
        {
            throw new IllegalArgumentException("'curve' is of an unsupported type");
        }
    }

    public ECCurve getCurve()
    {
        return curve;
    }

    public ECPoint getG()
    {
        return g.getPoint();
    }

    public BigInteger getN()
    {
        return n;
    }

    public BigInteger getH()
    {
        return h;
    }

    public byte[] getSeed()
    {
        return seed;
    }

    /**
     * Return the ASN.1 entry representing the Curve.
     *
     * @return the X9Curve for the curve in these parameters.
     */
    public X9Curve getCurveEntry()
    {
        return new X9Curve(curve, seed);
    }

    /**
     * Return the ASN.1 entry representing the FieldID.
     *
     * @return the X9FieldID for the FieldID in these parameters.
     */
    public X9FieldID getFieldIDEntry()
    {
        return fieldID;
    }

    /**
     * Return the ASN.1 entry representing the base point G.
     *
     * @return the X9ECPoint for the base point in these parameters.
     */
    public X9ECPoint getBaseEntry()
    {
        return g;
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

        v.add(new ASN1Integer(ONE));
        v.add(fieldID);
        v.add(new X9Curve(curve, seed));
        v.add(g);
        v.add(new ASN1Integer(n));

        if (h != null)
        {
            v.add(new ASN1Integer(h));
        }

        return new DERSequence(v);
    }
}
