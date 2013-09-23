package org.bouncycastle.math.ec;

import java.math.BigInteger;

import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.util.Arrays;

/**
 * base class for points on elliptic curves.
 */
public abstract class ECPoint
{
    protected static ECFieldElement[] EMPTY_ZS = new ECFieldElement[0];

    protected static ECFieldElement[] getInitialZCoords(ECCurve curve)
    {
        int coord = curve.getCoordinateSystem();
        if (coord == ECCurve.COORD_AFFINE)
        {
            return EMPTY_ZS;
        }

        ECFieldElement one = curve.fromBigInteger(ECConstants.ONE);

        switch (coord)
        {
        case ECCurve.COORD_HOMOGENEOUS:
        case ECCurve.COORD_JACOBIAN:
            return new ECFieldElement[]{ one };
        case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
            return new ECFieldElement[]{ one, one, one };
        case ECCurve.COORD_JACOBIAN_MODIFIED:
            return new ECFieldElement[]{ one, curve.getA() }; 
        default:
            throw new IllegalArgumentException("unknown coordinate system");
        }
    }

    protected ECCurve curve;
    protected ECFieldElement x;
    protected ECFieldElement y;
    protected ECFieldElement[] zs = null;

    protected boolean withCompression;

    protected PreCompInfo preCompInfo = null;

    private static X9IntegerConverter converter = new X9IntegerConverter();

    protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this(curve, x, y, getInitialZCoords(curve));
    }

    protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        this.curve = curve;
        this.x = x;
        this.y = y;
        this.zs = zs;
    }

    public ECCurve getCurve()
    {
        return curve;
    }

    /**
     * @deprecated Use getAffineXCoord or getXCoord instead
     */
    public ECFieldElement getX()
    {
        return x;
    }

    /**
     * @deprecated Use getAffineYCoord or getYCoord instead
     */
    public ECFieldElement getY()
    {
        return y;
    }

    public ECFieldElement getAffineXCoord()
    {
        assertNormalized();
        return x;
    }

    public ECFieldElement getAffineYCoord()
    {
        assertNormalized();
        return y;
    }

    public ECFieldElement getXCoord()
    {
        return x;
    }

    public ECFieldElement getYCoord()
    {
        return y;
    }

    public ECFieldElement getZCoord(int index)
    {
        return (index < 0 || index >= zs.length) ? null : zs[index];
    }

    public ECFieldElement[] getZCoords()
    {
        int zsLen = zs.length;
        if (zsLen == 0)
        {
            return zs;
        }
        ECFieldElement[] copy = new ECFieldElement[zsLen];
        System.arraycopy(zs, 0, copy, 0, zsLen);
        return copy;
    }

    protected void assertNormalized()
    {
        if (!isNormalized())
        {
            throw new IllegalStateException("point not in normal form");
        }
    }

    public boolean isNormalized()
    {
        return curve.getCoordinateSystem() == ECCurve.COORD_AFFINE || isInfinity() || zs[0].bitLength() == 1;
    }

    public ECPoint normalize()
    {
        if (isInfinity())
        {
            return this;
        }

        ECCurve curve = getCurve();
        int coord = curve.getCoordinateSystem();
        if (coord == ECCurve.COORD_AFFINE || zs.length == 0)
        {
            return this;
        }

        ECFieldElement Z1 = zs[0];
        if (Z1.bitLength() == 1)
        {
            return this;
        }

        ECFieldElement zInv = Z1.invert();

        switch (curve.getCoordinateSystem())
        {
        case ECCurve.COORD_HOMOGENEOUS:
            return createScaledPoint(zInv, zInv);
        case ECCurve.COORD_JACOBIAN:
        case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
        case ECCurve.COORD_JACOBIAN_MODIFIED:
        {
            ECFieldElement zInvSquared = zInv.square();
            ECFieldElement zInvCubed = zInvSquared.multiply(zInv);
            return createScaledPoint(zInvSquared, zInvCubed);
        }
        default:
            throw new IllegalArgumentException("unknown coordinate system");
        }
    }

    protected ECPoint createScaledPoint(ECFieldElement sx, ECFieldElement sy)
    {
        return curve.createPoint(getXCoord().multiply(sx).toBigInteger(), getYCoord().multiply(sy).toBigInteger());
    }

    public boolean isInfinity()
    {
        return (x == null && y == null) || (zs.length > 0 && zs[0].isZero());
    }

    public boolean isCompressed()
    {
        return withCompression;
    }

    public boolean equals(
        Object  other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof ECPoint))
        {
            return false;
        }

        ECPoint o = (ECPoint)other;

        if (this.isInfinity())
        {
            return o.isInfinity();
        }

        return x.equals(o.x) && y.equals(o.y) && Arrays.areEqual(zs, o.zs);
    }

    public int hashCode()
    {
        if (this.isInfinity())
        {
            return 0;
        }
        
        return x.hashCode() ^ y.hashCode() ^ Arrays.hashCode(zs);
    }

    /**
     * Sets the <code>PreCompInfo</code>. Used by <code>ECMultiplier</code>s
     * to save the precomputation for this <code>ECPoint</code> to store the
     * precomputation result for use by subsequent multiplication.
     * @param preCompInfo The values precomputed by the
     * <code>ECMultiplier</code>.
     */
    void setPreCompInfo(PreCompInfo preCompInfo)
    {
        this.preCompInfo = preCompInfo;
    }

    public byte[] getEncoded()
    {
        return getEncoded(withCompression);
    }

    /**
     * return the field element encoded with point compression. (S 4.3.6)
     */
    public byte[] getEncoded(boolean compressed)
    {
        if (this.isInfinity())
        {
            return new byte[1];
        }

        ECPoint normed = normalize();
        ECFieldElement x = normed.getAffineXCoord();

        int length = converter.getByteLength(x);
        byte[] X = converter.integerToBytes(x.toBigInteger(), length);

        if (compressed)
        {
            byte[] PO = new byte[X.length + 1];
            PO[0] = (byte)(normed.getCompressionYTilde() ? 0x03 : 0x02);
            System.arraycopy(X, 0, PO, 1, X.length);
            return PO;
        }

        ECFieldElement y = normed.getAffineYCoord();
        byte[] Y = converter.integerToBytes(y.toBigInteger(), length);
        byte[] PO = new byte[X.length + Y.length + 1];
        PO[0] = 0x04;
        System.arraycopy(X, 0, PO, 1, X.length);
        System.arraycopy(Y, 0, PO, X.length + 1, Y.length);
        return PO;
    }

    protected abstract boolean getCompressionYTilde();

    public abstract ECPoint add(ECPoint b);
    public abstract ECPoint subtract(ECPoint b);
    public abstract ECPoint negate();
    public abstract ECPoint twice();

    public ECPoint twicePlus(ECPoint b)
    {
        return twice().add(b);
    }

    public ECPoint threeTimes()
    {
        return twicePlus(this);
    }

    /**
     * Multiplies this <code>ECPoint</code> by the given number.
     * @param k The multiplicator.
     * @return <code>k * this</code>.
     */
    public ECPoint multiply(BigInteger k)
    {
        if (k.signum() < 0)
        {
            throw new IllegalArgumentException("The multiplicator cannot be negative");
        }

        if (this.isInfinity())
        {
            return this;
        }

        if (k.signum() == 0)
        {
            return getCurve().getInfinity();
        }

        return getCurve().getMultiplier().multiply(this, k, preCompInfo);
    }

    /**
     * Elliptic curve points over Fp
     */
    public static class Fp extends ECPoint
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
        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y)
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
        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
        {
            super(curve, x, y);

            if ((x != null && y == null) || (x == null && y != null))
            {
                throw new IllegalArgumentException("Exactly one of the field elements is null");
            }

            this.withCompression = withCompression;
        }

        protected Fp(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
        {
            super(curve, x, y, zs);
        }

        protected boolean getCompressionYTilde()
        {
            return getAffineYCoord().testBitZero();
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

            ECCurve curve = getCurve();
            int coord = curve.getCoordinateSystem();

            if (coord == ECCurve.COORD_JACOBIAN)
            {
                ECFieldElement X1 = this.x, Y1 = this.y, Z1 = this.zs[0];
                ECFieldElement X2 = b.x, Y2 = b.y, Z2 = b.zs[0];

                boolean Z2IsOne = Z2.bitLength() == 1;

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

                ECFieldElement Z1Squared = Z1.square();
                ECFieldElement U2 = Z1Squared.multiply(X2);
                ECFieldElement H = U1.subtract(U2);
                ECFieldElement Z1Cubed = Z1Squared.multiply(Z1);
                ECFieldElement S2 = Z1Cubed.multiply(Y2);
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
                ECFieldElement Y3 = V.subtract(X3).multiply(R).subtract(S1.multiply(G));

                ECFieldElement Z3;
                if (Z2IsOne)
                {
                    Z3 = Z1.multiply(H);
                }
                else
                {
//                    Z3 = Z1.multiply(Z2).multiply(H);
                    X3 = four(X3);
                    Y3 = eight(Y3);
                    Z3 = doubleProductFromSquares(Z1, Z2, Z1Squared, Z2Squared).multiply(H);
                }

                return new ECPoint.Fp(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }

            ECFieldElement dx = b.x.subtract(this.x), dy = b.y.subtract(this.y);

            if (dx.isZero())
            {
                if (dy.isZero())
                {
                    // this == b, i.e. this must be doubled
                    return twice();
                }

                // this == -b, i.e. the result is the point at infinity
                return curve.getInfinity();
            }

            ECFieldElement gamma = dy.divide(dx);
            ECFieldElement x3 = gamma.square().subtract(this.x).subtract(b.x);
            ECFieldElement y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

            return new ECPoint.Fp(curve, x3, y3, withCompression);
        }

        // B.3 pg 62
        public ECPoint twice()
        {
            if (this.isInfinity())
            {
                // Twice identity element (point at infinity) is identity
                return this;
            }
            if (this.y.isZero()) 
            {
                // if y1 == 0, then (x1, y1) == (x1, -y1)
                // and hence this = -this and thus 2(x1, y1) == infinity
                return getCurve().getInfinity();
            }

            ECCurve curve = getCurve();
            int coord = curve.getCoordinateSystem();

            if (coord == ECCurve.COORD_JACOBIAN)
            {
                ECFieldElement X1 = this.x, Y1 = this.y, Z1 = this.zs[0];

                ECFieldElement Y1Squared = Y1.square();
                ECFieldElement Z1Squared = Z1.square();

                ECFieldElement a4 = curve.getA();
                ECFieldElement M;
                if (a4.add(curve.fromBigInteger(BigInteger.valueOf(3))).isZero())
                {
                    M = three(X1.add(Z1Squared).multiply(X1.subtract(Z1Squared)));
                }
                else
                {
                    ECFieldElement X1Squared = X1.square();
                    M = three(X1Squared).add(Z1Squared.square().multiply(a4));
                }

                ECFieldElement T = Y1Squared.square();
                ECFieldElement S = four(Y1Squared.multiply(X1));

                ECFieldElement X3 = M.square().subtract(two(S));
                ECFieldElement Y3 = S.subtract(X3).multiply(M).subtract(eight(T));

//                ECFieldElement Z3 = two(Y1.multiply(Z1));
                ECFieldElement Z3 = doubleProductFromSquares(Y1, Z1, Y1Squared, Z1Squared);

                return new ECPoint.Fp(curve, X3, Y3, new ECFieldElement[]{ Z3 });
            }

            ECFieldElement X = this.x.square();
            ECFieldElement gamma = three(X).add(getCurve().getA()).divide(two(this.y));
            ECFieldElement x3 = gamma.square().subtract(two(this.x));
            ECFieldElement y3 = gamma.multiply(this.x.subtract(x3)).subtract(this.y);

            return new ECPoint.Fp(curve, x3, y3, this.withCompression);
        }

        public ECPoint twicePlus(ECPoint b)
        {
            if (this.isInfinity())
            {
                return b;
            }
            if (b.isInfinity())
            {
                return twice();
            }
            if (this == b)
            {
                return threeTimes();
            }

            ECCurve curve = getCurve();
            int coord = curve.getCoordinateSystem();

            if (coord != ECCurve.COORD_AFFINE)
            {
                return twice().add(b);
            }

            /*
             * Optimized calculation of 2P + Q, as described in "Trading Inversions for
             * Multiplications in Elliptic Curve Cryptography", by Ciet, Joye, Lauter, Montgomery.
             */
            ECFieldElement dx = b.x.subtract(this.x), dy = b.y.subtract(this.y);

            if (dx.isZero())
            {
                if (dy.isZero())
                {
                    // this == b i.e. the result is 3P
                    return threeTimes();
                }

                // this == -b, i.e. the result is P
                return this;
            }

            ECFieldElement X = dx.square(), Y = dy.square();
            ECFieldElement d = X.multiply(two(this.x).add(b.x)).subtract(Y);
            if (d.isZero())
            {
                return curve.getInfinity();
            }
            ECFieldElement D = d.multiply(dx);
            ECFieldElement I = D.invert();
            ECFieldElement lambda1 = d.multiply(I).multiply(dy);
            ECFieldElement lambda2 = two(this.y).multiply(X).multiply(dx).multiply(I).subtract(lambda1);
            ECFieldElement x4 = (lambda2.subtract(lambda1)).multiply(lambda1.add(lambda2)).add(b.x);
            ECFieldElement y4 = (this.x.subtract(x4)).multiply(lambda2).subtract(this.y); 
            return new ECPoint.Fp(curve, x4, y4, this.withCompression);
        }

        public ECPoint threeTimes()
        {
            if (this.isInfinity() || this.y.isZero())
            {
                return this;
            }

            ECCurve curve = getCurve();
            int coord = curve.getCoordinateSystem();

            if (coord != ECCurve.COORD_AFFINE)
            {
                return twice().add(this);
            }

            ECFieldElement _2y = two(this.y); 
            ECFieldElement X = _2y.square();
            ECFieldElement Z = three(this.x.square()).add(getCurve().getA());
            ECFieldElement Y = Z.square();

            ECFieldElement d = three(this.x).multiply(X).subtract(Y);
            if (d.isZero())
            {
                return getCurve().getInfinity();
            }

            ECFieldElement D = d.multiply(_2y); 
            ECFieldElement I = D.invert();
            ECFieldElement lambda1 = d.multiply(I).multiply(Z);
            ECFieldElement lambda2 = X.square().multiply(I).subtract(lambda1);

            ECFieldElement x4 = (lambda2.subtract(lambda1)).multiply(lambda1.add(lambda2)).add(this.x);
            ECFieldElement y4 = (this.x.subtract(x4)).multiply(lambda2).subtract(this.y); 
            return new ECPoint.Fp(curve, x4, y4, this.withCompression);
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

        protected ECFieldElement doubleProductFromSquares(ECFieldElement a, ECFieldElement b,
            ECFieldElement aSquared, ECFieldElement bSquared)
        {
            /*
             * NOTE: If squaring in the field is faster than multiplication, then this is a quicker
             * way to calculate 2.A.B, if A^2 and B^2 are already known.
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

            if (getCurve().getCoordinateSystem() != ECCurve.COORD_AFFINE)
            {
                return new ECPoint.Fp(curve, this.x, this.y.negate(), this.zs);
            }

            return new ECPoint.Fp(curve, this.x, this.y.negate(), this.withCompression);
        }
    }

    /**
     * Elliptic curve points over F2m
     */
    public static class F2m extends ECPoint
    {
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         * 
         * @deprecated Use ECCurve.createPoint to construct points
         */
        public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y)
        {
            this(curve, x, y, false);
        }
        
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         * @param withCompression true if encode with point compression.
         * 
         * @deprecated per-point compression property will be removed, refer {@link #getEncoded(boolean)}
         */
        public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
        {
            super(curve, x, y);

            if ((x != null && y == null) || (x == null && y != null))
            {
                throw new IllegalArgumentException("Exactly one of the field elements is null");
            }
            
            if (x != null)
            {
                // Check if x and y are elements of the same field
                ECFieldElement.F2m.checkFieldElements(this.x, this.y);
    
                // Check if x and a are elements of the same field
                if (curve != null)
                {
                    ECFieldElement.F2m.checkFieldElements(this.x, this.curve.getA());
                }
            }
            
            this.withCompression = withCompression;
        }

        protected boolean getCompressionYTilde()
        {
            ECFieldElement x = getAffineXCoord(), y = getAffineYCoord();
            return !x.isZero() && y.divide(x).testBitZero();
        }

        /**
         * Check, if two <code>ECPoint</code>s can be added or subtracted.
         * @param a The first <code>ECPoint</code> to check.
         * @param b The second <code>ECPoint</code> to check.
         * @throws IllegalArgumentException if <code>a</code> and <code>b</code>
         * cannot be added.
         */
        private static void checkPoints(ECPoint a, ECPoint b)
        {
            // Check, if points are on the same curve
            if (a.curve != b.curve)
            {
                throw new IllegalArgumentException("Only points on the same "
                        + "curve can be added or subtracted");
            }

//            ECFieldElement.F2m.checkFieldElements(a.x, b.x);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#add(org.bouncycastle.math.ec.ECPoint)
         */
        public ECPoint add(ECPoint b)
        {
            checkPoints(this, b);
            return addSimple((ECPoint.F2m)b);
        }

        /**
         * Adds another <code>ECPoints.F2m</code> to <code>this</code> without
         * checking if both points are on the same curve. Used by multiplication
         * algorithms, because there all points are a multiple of the same point
         * and hence the checks can be omitted.
         * @param b The other <code>ECPoints.F2m</code> to add to
         * <code>this</code>.
         * @return <code>this + b</code>
         */
        public ECPoint.F2m addSimple(ECPoint.F2m b)
        {
            ECPoint.F2m other = b;
            if (this.isInfinity())
            {
                return other;
            }

            if (other.isInfinity())
            {
                return this;
            }

            ECFieldElement.F2m x2 = (ECFieldElement.F2m)other.getXCoord();
            ECFieldElement.F2m y2 = (ECFieldElement.F2m)other.getYCoord();

            // Check if other = this or other = -this
            if (this.x.equals(x2))
            {
                if (this.y.equals(y2))
                {
                    // this = other, i.e. this must be doubled
                    return (ECPoint.F2m)this.twice();
                }

                // this = -other, i.e. the result is the point at infinity
                return (ECPoint.F2m)this.curve.getInfinity();
            }

            ECFieldElement.F2m lambda
                = (ECFieldElement.F2m)(this.y.add(y2)).divide(this.x.add(x2));

            ECFieldElement.F2m x3
                = (ECFieldElement.F2m)lambda.square().add(lambda).add(this.x).add(x2).add(this.curve.getA());

            ECFieldElement.F2m y3
                = (ECFieldElement.F2m)lambda.multiply(this.x.add(x3)).add(x3).add(this.y);

            return new ECPoint.F2m(curve, x3, y3, withCompression);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#subtract(org.bouncycastle.math.ec.ECPoint)
         */
        public ECPoint subtract(ECPoint b)
        {
            checkPoints(this, b);
            return subtractSimple((ECPoint.F2m)b);
        }

        /**
         * Subtracts another <code>ECPoints.F2m</code> from <code>this</code>
         * without checking if both points are on the same curve. Used by
         * multiplication algorithms, because there all points are a multiple
         * of the same point and hence the checks can be omitted.
         * @param b The other <code>ECPoints.F2m</code> to subtract from
         * <code>this</code>.
         * @return <code>this - b</code>
         */
        public ECPoint.F2m subtractSimple(ECPoint.F2m b)
        {
            if (b.isInfinity())
            {
                return this;
            }

            // Add -b
            return addSimple((ECPoint.F2m)b.negate());
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#twice()
         */
        public ECPoint twice()
        {
            if (this.isInfinity()) 
            {
                // Twice identity element (point at infinity) is identity
                return this;
            }

            if (this.x.isZero()) 
            {
                // if x1 == 0, then (x1, y1) == (x1, x1 + y1)
                // and hence this = -this and thus 2(x1, y1) == infinity
                return this.curve.getInfinity();
            }

            ECFieldElement.F2m lambda
                = (ECFieldElement.F2m)this.x.add(this.y.divide(this.x));

            ECFieldElement.F2m x3
                = (ECFieldElement.F2m)lambda.square().add(lambda).
                    add(this.curve.getA());

            ECFieldElement ONE = this.curve.fromBigInteger(ECConstants.ONE);
            ECFieldElement.F2m y3
                = (ECFieldElement.F2m)this.x.square().add(
                    x3.multiply(lambda.add(ONE)));

            return new ECPoint.F2m(this.curve, x3, y3, withCompression);
        }

        public ECPoint negate()
        {
            if (this.isInfinity())
            {
                return this;
            }

            return new ECPoint.F2m(curve, this.getXCoord(), this.getYCoord().add(this.getXCoord()), withCompression);
        }
    }
}
