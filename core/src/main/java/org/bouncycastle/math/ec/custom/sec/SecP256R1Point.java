package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class SecP256R1Point extends ECPoint
{
    /**
     * Create a point which encodes with point compression.
     * 
     * @param curve
     *            the curve to use
     * @param x
     *            affine x co-ordinate
     * @param y
     *            affine y co-ordinate
     * 
     * @deprecated Use ECCurve.createPoint to construct points
     */
    public SecP256R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this(curve, x, y, false);
    }

    /**
     * Create a point that encodes with or without point compresion.
     * 
     * @param curve
     *            the curve to use
     * @param x
     *            affine x co-ordinate
     * @param y
     *            affine y co-ordinate
     * @param withCompression
     *            if true encode with point compression
     * 
     * @deprecated per-point compression property will be removed, refer
     *             {@link #getEncoded(boolean)}
     */
    public SecP256R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        super(curve, x, y);

        if ((x != null && y == null) || (x == null && y != null))
        {
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        this.withCompression = withCompression;
    }

    SecP256R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        super(curve, x, y, zs);

        this.withCompression = withCompression;
    }

    protected boolean getCompressionYTilde()
    {
        return this.getAffineYCoord().testBitZero();
    }

    // B.3 pg 62
    public ECPoint add(ECPoint b)
    {
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return this;
        }
        if (this == b)
        {
            return twice();
        }

        ECCurve curve = this.getCurve();

        SecP256R1FieldElement X1 = (SecP256R1FieldElement)this.x, Y1 = (SecP256R1FieldElement)this.y;
        SecP256R1FieldElement X2 = (SecP256R1FieldElement)b.getXCoord(), Y2 = (SecP256R1FieldElement)b.getYCoord();

        SecP256R1FieldElement Z1 = (SecP256R1FieldElement)this.zs[0];
        SecP256R1FieldElement Z2 = (SecP256R1FieldElement)b.getZCoord(0);

        boolean Z1IsOne = Z1.isOne();
        int[] Z1Squared, U2, S2;
        if (Z1IsOne)
        {
            Z1Squared = Z1.x;
            U2 = X2.x;
            S2 = Y2.x;
        }
        else
        {
//            Z1Squared = Z1.square();
            Z1Squared = Nat256.create();
            SecP256R1Field.square(Z1.x, Z1Squared);

//            U2 = Z1Squared.multiply(X2);
            U2 = Nat256.create();
            SecP256R1Field.multiply(Z1Squared, X2.x, U2);

//            ECFieldElement Z1Cubed = Z1Squared.multiply(Z1);
//            S2 = Z1Cubed.multiply(Y2);
            S2 = Nat256.create();
            SecP256R1Field.multiply(Z1Squared, Z1.x, S2);
            SecP256R1Field.multiply(S2, Y2.x, S2);
        }

        boolean Z2IsOne = Z2.isOne();
        int[] Z2Squared, U1, S1;
        if (Z2IsOne)
        {
            Z2Squared = Z2.x;
            U1 = X1.x;
            S1 = Y1.x;
        }
        else
        {
//            Z2Squared = Z2.square();
            Z2Squared = Nat256.create();
            SecP256R1Field.square(Z2.x, Z2Squared);

//            U1 = Z2Squared.multiply(X1);
            U1 = Nat256.create();
            SecP256R1Field.multiply(Z2Squared, X1.x, U1);

//            ECFieldElement Z2Cubed = Z2Squared.multiply(Z2);
//            S1 = Z2Cubed.multiply(Y1);
            S1 = Nat256.create();
            SecP256R1Field.multiply(Z2Squared, Z2.x, S1);
            SecP256R1Field.multiply(S1, Y1.x, S1);
        }

//        ECFieldElement H = U1.subtract(U2);
        int[] H = Nat256.create();
        SecP256R1Field.subtract(U1, U2, H);

//        ECFieldElement R = S1.subtract(S2);
        int[] R = Nat256.create();
        SecP256R1Field.subtract(S1, S2, R);

        // Check if b == this or b == -this
//        if (H.isZero())
        if (Nat256.isZero(H))
        {
//            if (R.isZero())
            if (Nat256.isZero(R))
            {
                // this == b, i.e. this must be doubled
                return this.twice();
            }

            // this == -b, i.e. the result is the point at infinity
            return curve.getInfinity();
        }

//        ECFieldElement HSquared = H.square();
        int[] HSquared = Nat256.create();
        SecP256R1Field.square(H, HSquared);

//        ECFieldElement G = HSquared.multiply(H);
        int[] G = Nat256.create();
        SecP256R1Field.multiply(HSquared, H, G);

//        ECFieldElement V = HSquared.multiply(U1);
        int[] V = Nat256.create();
        SecP256R1Field.multiply(HSquared, U1, V);

//        ECFieldElement X3 = R.square().add(G).subtract(two(V));
        SecP256R1FieldElement X3 = new SecP256R1FieldElement(HSquared);
        SecP256R1Field.square(R, X3.x);
        SecP256R1Field.add(X3.x, G, X3.x);
        SecP256R1Field.subtract(X3.x, V, X3.x);
        SecP256R1Field.subtract(X3.x, V, X3.x);

//        ECFieldElement Y3 = V.subtract(X3).multiply(R).subtract(S1.multiply(G));
        int[] t1 = Nat256.create();
        SecP256R1Field.multiply(S1, G, t1);
        SecP256R1FieldElement Y3 = new SecP256R1FieldElement(G);
        SecP256R1Field.subtract(V, X3.x, Y3.x);
        SecP256R1Field.multiply(Y3.x, R, Y3.x);
        SecP256R1Field.subtract(Y3.x, t1, Y3.x);

//        ECFieldElement Z3 = H;
        SecP256R1FieldElement Z3 = new SecP256R1FieldElement(H);
        if (!Z1IsOne)
        {
//            Z3 = Z3.multiply(Z1);
            SecP256R1Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        if (!Z2IsOne)
        {
//            Z3 = Z3.multiply(Z2);
            SecP256R1Field.multiply(Z3.x, Z2.x, Z3.x);
        }

        ECFieldElement[] zs = new ECFieldElement[]{ Z3 };

        return new SecP256R1Point(curve, X3, Y3, zs, this.withCompression);
    }

    // B.3 pg 62
    public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECCurve curve = this.getCurve();

        SecP256R1FieldElement Y1 = (SecP256R1FieldElement)this.y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        SecP256R1FieldElement X1 = (SecP256R1FieldElement)this.x, Z1 = (SecP256R1FieldElement)this.zs[0];

//        ECFieldElement Y1Squared = Y1.square();
        int[] Y1Squared = Nat256.create();
        SecP256R1Field.square(Y1.x, Y1Squared);

//        ECFieldElement T = Y1Squared.square();
        int[] T = Nat256.create();
        SecP256R1Field.square(Y1Squared, T);

        boolean Z1IsOne = Z1.isOne();

//        ECFieldElement Z1Squared = Z1IsOne ? Z1 : Z1.square();
        int[] Z1Squared = Z1.x;
        if (!Z1IsOne)
        {
            Z1Squared = Nat256.create();
            SecP256R1Field.square(Z1.x, Z1Squared);
        }

//        ECFieldElement M = three(X1.add(Z1Squared).multiply(X1.subtract(Z1Squared)));
        int[] t1 = Nat256.create();
        SecP256R1Field.subtract(X1.x, Z1Squared, t1);
        int[] M = Nat256.create();
        SecP256R1Field.add(X1.x, Z1Squared, M);
        SecP256R1Field.multiply(M, t1, M);
        SecP256R1Field.add(M, M, t1);
        SecP256R1Field.add(M, t1, M);

//        ECFieldElement S = four(Y1Squared.multiply(X1));
        int[] S = Y1Squared;
        SecP256R1Field.multiply(Y1Squared, X1.x, S);
        SecP256R1Field.add(S, S, S);
        SecP256R1Field.add(S, S, S);

        // eight(T)
        SecP256R1Field.add(T, T, t1);
        SecP256R1Field.add(t1, t1, t1);
        SecP256R1Field.add(t1, t1, t1);

//        ECFieldElement X3 = M.square().subtract(two(S));
        SecP256R1FieldElement X3 = new SecP256R1FieldElement(T);
        SecP256R1Field.square(M, X3.x);
        SecP256R1Field.subtract(X3.x, S, X3.x);
        SecP256R1Field.subtract(X3.x, S, X3.x);

//        ECFieldElement Y3 = S.subtract(X3).multiply(M).subtract(eight(T));
        SecP256R1FieldElement Y3 = new SecP256R1FieldElement(S);
        SecP256R1Field.subtract(S, X3.x, Y3.x);
        SecP256R1Field.multiply(Y3.x, M, Y3.x);
        SecP256R1Field.subtract(Y3.x, t1, Y3.x);

//        ECFieldElement Z3 = two(Y1);
        SecP256R1FieldElement Z3 = new SecP256R1FieldElement(M);
        SecP256R1Field.add(Y1.x, Y1.x, Z3.x);
        if (!Z1IsOne)
        {
//            Z3 = Z3.multiply(Z1);
            SecP256R1Field.multiply(Z3.x, Z1.x, Z3.x);
        }

        return new SecP256R1Point(curve, X3, Y3, new ECFieldElement[]{ Z3 }, this.withCompression);
    }

    public ECPoint twicePlus(ECPoint b)
    {
        if (this == b)
        {
            return threeTimes();
        }
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return twice();
        }

        ECFieldElement Y1 = this.y;
        if (Y1.isZero())
        {
            return b;
        }

        return twice().add(b);
    }

    public ECPoint threeTimes()
    {
        if (this.isInfinity() || this.y.isZero())
        {
            return this;
        }

        // NOTE: Be careful about recursions between twicePlus and threeTimes
        return twice().add(this);
    }

    // D.3.2 pg 102 (see Note:)
    public ECPoint subtract(ECPoint b)
    {
        if (b.isInfinity())
        {
            return this;
        }

        // Add -b
        return add(b.negate());
    }

    public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }

        return new SecP256R1Point(curve, this.x, this.y.negate(), this.zs, this.withCompression);
    }
}
