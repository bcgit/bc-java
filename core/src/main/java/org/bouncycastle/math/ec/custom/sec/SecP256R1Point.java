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

        ECFieldElement X1 = this.x, Y1 = this.y;
        ECFieldElement X2 = b.getXCoord(), Y2 = b.getYCoord();

        ECFieldElement Z1 = this.zs[0];
        ECFieldElement Z2 = b.getZCoord(0);

        boolean Z1IsOne = Z1.isOne();

        ECFieldElement X3, Y3, Z3;

        // if (!Z1IsOne && Z1.equals(Z2))
        // {
        // // TODO Make this available as public method coZAdd?
        //
        // ECFieldElement dx = X1.subtract(X2), dy = Y1.subtract(Y2);
        // if (dx.isZero())
        // {
        // if (dy.isZero())
        // {
        // return twice();
        // }
        // return curve.getInfinity();
        // }
        //
        // ECFieldElement C = dx.square();
        // ECFieldElement W1 = X1.multiply(C), W2 = X2.multiply(C);
        // ECFieldElement A1 = W1.subtract(W2).multiply(Y1);
        //
        // X3 = dy.square().subtract(W1).subtract(W2);
        // Y3 = W1.subtract(X3).multiply(dy).subtract(A1);
        // Z3 = dx;
        //
        // if (Z1IsOne)
        // {
        // Z3Squared = C;
        // }
        // else
        // {
        // Z3 = Z3.multiply(Z1);
        // }
        // }
        // else
        {
            ECFieldElement Z1Squared, U2, S2;
            if (Z1IsOne)
            {
                Z1Squared = Z1;
                U2 = X2;
                S2 = Y2;
            }
            else
            {
                Z1Squared = Z1.square();
                U2 = Z1Squared.multiply(X2);
                ECFieldElement Z1Cubed = Z1Squared.multiply(Z1);
                S2 = Z1Cubed.multiply(Y2);
            }

            boolean Z2IsOne = Z2.isOne();
            ECFieldElement Z2Squared, U1, S1;
            if (Z2IsOne)
            {
                Z2Squared = Z2;
                U1 = X1;
                S1 = Y1;
            }
            else
            {
                Z2Squared = Z2.square();
                U1 = Z2Squared.multiply(X1);
                ECFieldElement Z2Cubed = Z2Squared.multiply(Z2);
                S1 = Z2Cubed.multiply(Y1);
            }

            ECFieldElement H = U1.subtract(U2);
            ECFieldElement R = S1.subtract(S2);

            // Check if b == this or b == -this
            if (H.isZero())
            {
                if (R.isZero())
                {
                    // this == b, i.e. this must be doubled
                    return this.twice();
                }

                // this == -b, i.e. the result is the point at infinity
                return curve.getInfinity();
            }

            ECFieldElement HSquared = H.square();
            ECFieldElement G = HSquared.multiply(H);
            ECFieldElement V = HSquared.multiply(U1);

            X3 = R.square().add(G).subtract(two(V));
            Y3 = V.subtract(X3).multiply(R).subtract(S1.multiply(G));

            Z3 = H;
            if (!Z1IsOne)
            {
                Z3 = Z3.multiply(Z1);
            }
            if (!Z2IsOne)
            {
                Z3 = Z3.multiply(Z2);
            }
        }

        ECFieldElement[] zs = new ECFieldElement[] { Z3 };

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

        ECFieldElement Y1 = this.y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        ECFieldElement X1 = this.x, Z1 = this.zs[0];

        ECFieldElement Y1Squared = Y1.square();
        ECFieldElement T = Y1Squared.square();

        boolean Z1IsOne = Z1.isOne();

        ECFieldElement Z1Squared = Z1IsOne ? Z1 : Z1.square();
        ECFieldElement M = three(X1.add(Z1Squared).multiply(X1.subtract(Z1Squared)));
        ECFieldElement S = four(Y1Squared.multiply(X1));

        ECFieldElement X3 = M.square().subtract(two(S));
        ECFieldElement Y3 = S.subtract(X3).multiply(M).subtract(eight(T));

        ECFieldElement Z3 = two(Y1);
        if (!Z1IsOne)
        {
            Z3 = Z3.multiply(Z1);
        }

        return new SecP256R1Point(curve, X3, Y3, new ECFieldElement[] { Z3 }, this.withCompression);
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

    protected ECFieldElement two(ECFieldElement x)
    {
        return x.add(x);
    }

    protected ECFieldElement three(ECFieldElement x)
    {
        return two(x).add(x);
    }

    protected ECFieldElement four(ECFieldElement x)
    {
        return two(two(x));
    }

    protected ECFieldElement eight(ECFieldElement x)
    {
        return four(two(x));
    }

    protected ECFieldElement doubleProductFromSquares(ECFieldElement a, ECFieldElement b, ECFieldElement aSquared,
        ECFieldElement bSquared)
    {
        /*
         * NOTE: If squaring in the field is faster than multiplication, then this is a quicker way
         * to calculate 2.A.B, if A^2 and B^2 are already known.
         */
        return a.add(b).square().subtract(aSquared).subtract(bSquared);
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
