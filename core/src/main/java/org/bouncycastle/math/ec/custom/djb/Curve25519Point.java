package org.bouncycastle.math.ec.custom.djb;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class Curve25519Point extends ECPoint
{
    /**
     * Create a point which encodes with point compression.
     * 
     * @param curve the curve to use
     * @param x affine x co-ordinate
     * @param y affine y co-ordinate
     * 
     * @deprecated Use ECCurve.createPoint to construct points
     */
    public Curve25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this(curve, x, y, false);
    }

    /**
     * Create a point that encodes with or without point compresion.
     * 
     * @param curve the curve to use
     * @param x affine x co-ordinate
     * @param y affine y co-ordinate
     * @param withCompression if true encode with point compression
     * 
     * @deprecated per-point compression property will be removed, refer {@link #getEncoded(boolean)}
     */
    public Curve25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        super(curve, x, y);

        if ((x == null) != (y == null))
        {
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        this.withCompression = withCompression;
    }

    Curve25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        super(curve, x, y, zs);

        this.withCompression = withCompression;
    }

    protected ECPoint detach()
    {
        return new Curve25519Point(null, getAffineXCoord(), getAffineYCoord());
    }

    protected boolean getCompressionYTilde()
    {
        return this.getAffineYCoord().testBitZero();
    }

    public ECFieldElement getZCoord(int index)
    {
        if (index == 1)
        {
            return getJacobianModifiedW();
        }

        return super.getZCoord(index);
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

        ECFieldElement X1 = this.x, Y1 = this.y;
        ECFieldElement X2 = b.getXCoord(), Y2 = b.getYCoord();

        ECFieldElement Z1 = this.zs[0];
        ECFieldElement Z2 = b.getZCoord(0);

        boolean Z1IsOne = Z1.isOne();

        ECFieldElement Z1Squared, U2, S2;
        if (Z1IsOne)
        {
            Z1Squared = Z1; U2 = X2; S2 = Y2;
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
            Z2Squared = Z2; U1 = X1; S1 = Y1;
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

        ECFieldElement X3 = R.square().add(G).subtract(two(V));
        ECFieldElement Y3 = V.subtract(X3).multiplyMinusProduct(R, G, S1);

        ECFieldElement Z3 = H;
        if (!Z1IsOne)
        {
            Z3 = Z3.multiply(Z1);
        }
        if (!Z2IsOne)
        {
            Z3 = Z3.multiply(Z2);
        }

        ECFieldElement Z3Squared = (Z3 == H) ? HSquared : null;

        // TODO If the result will only be used in a subsequent addition, we don't need W3
        ECFieldElement W3 = calculateJacobianModifiedW(Z3, Z3Squared);

        ECFieldElement[] zs = new ECFieldElement[]{ Z3, W3 };

        return new Curve25519Point(curve, X3, Y3, zs, this.withCompression);
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

        return twiceJacobianModified(true);
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

        return twiceJacobianModified(false).add(b);
    }

    public ECPoint threeTimes()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECFieldElement Y1 = this.y;
        if (Y1.isZero())
        {
            return this;
        }

        return twiceJacobianModified(false).add(this);
    }

    protected ECFieldElement two(ECFieldElement x)
    {
        return x.add(x);
    }

    protected ECFieldElement three(ECFieldElement x)
    {
        return two(x).add(x);
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

        ECCurve curve = this.getCurve();
        int coord = curve.getCoordinateSystem();

        if (ECCurve.COORD_AFFINE != coord)
        {
            return new Curve25519Point(curve, this.x, this.y.negate(), this.zs, this.withCompression);
        }

        return new Curve25519Point(curve, this.x, this.y.negate(), this.withCompression);
    }

    protected ECFieldElement calculateJacobianModifiedW(ECFieldElement Z, ECFieldElement ZSquared)
    {
        ECFieldElement a4 = this.getCurve().getA();
        if (Z.isOne())
        {
            return a4;
        }

        if (ZSquared == null)
        {
            ZSquared = Z.square();
        }

        return ZSquared.square().multiply(a4);
    }

    protected ECFieldElement getJacobianModifiedW()
    {
        ECFieldElement W = this.zs[1];
        if (W == null)
        {
            // NOTE: Rarely, twicePlus will result in the need for a lazy W1 calculation here
            this.zs[1] = W = calculateJacobianModifiedW(this.zs[0], null);
        }
        return W;
    }

    protected Curve25519Point twiceJacobianModified(boolean calculateW)
    {
        ECFieldElement X1 = this.x, Y1 = this.y, Z1 = this.zs[0], W1 = getJacobianModifiedW();

        ECFieldElement X1Squared = X1.square();
        ECFieldElement M = three(X1Squared).add(W1);
        ECFieldElement _2Y1 = two(Y1);
        ECFieldElement _2Y1Squared = _2Y1.multiply(Y1);
        ECFieldElement S = two(X1.multiply(_2Y1Squared));
        ECFieldElement X3 = M.square().subtract(two(S));
        ECFieldElement _4T = _2Y1Squared.square();
        ECFieldElement _8T = two(_4T);
        ECFieldElement Y3 = M.multiply(S.subtract(X3)).subtract(_8T);
        ECFieldElement W3 = calculateW ? two(_8T.multiply(W1)) : null;
        ECFieldElement Z3 = Z1.isOne() ? _2Y1 : _2Y1.multiply(Z1);

        return new Curve25519Point(this.getCurve(), X3, Y3, new ECFieldElement[]{ Z3, W3 }, this.withCompression);
    }
}
