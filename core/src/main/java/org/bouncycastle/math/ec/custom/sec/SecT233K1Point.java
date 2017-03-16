package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPoint.AbstractF2m;

public class SecT233K1Point extends AbstractF2m
{
    /**
     * @deprecated Use ECCurve.createPoint to construct points
     */
    public SecT233K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this(curve, x, y, false);
    }

    /**
     * @deprecated per-point compression property will be removed, refer {@link #getEncoded(boolean)}
     */
    public SecT233K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        super(curve, x, y);

        if ((x == null) != (y == null))
        {
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        this.withCompression = withCompression;
    }

    SecT233K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        super(curve, x, y, zs);

        this.withCompression = withCompression;
    }

    protected ECPoint detach()
    {
        return new SecT233K1Point(null, this.getAffineXCoord(), this.getAffineYCoord()); // earlier JDK
    }

    public ECFieldElement getYCoord()
    {
        ECFieldElement X = x, L = y;

        if (this.isInfinity() || X.isZero())
        {
            return L;
        }

        // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
        ECFieldElement Y = L.add(X).multiply(X);

        ECFieldElement Z = zs[0];
        if (!Z.isOne())
        {
            Y = Y.divide(Z);
        }

        return Y;
    }

    protected boolean getCompressionYTilde()
    {
        ECFieldElement X = this.getRawXCoord();
        if (X.isZero())
        {
            return false;
        }

        ECFieldElement Y = this.getRawYCoord();

        // Y is actually Lambda (X + Y/X) here
        return Y.testBitZero() != X.testBitZero();
    }

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

        ECCurve curve = this.getCurve();

        ECFieldElement X1 = this.x;
        ECFieldElement X2 = b.getRawXCoord();

        if (X1.isZero())
        {
            if (X2.isZero())
            {
                return curve.getInfinity();
            }

            return b.add(this);
        }

        ECFieldElement L1 = this.y, Z1 = this.zs[0];
        ECFieldElement L2 = b.getRawYCoord(), Z2 = b.getZCoord(0);

        boolean Z1IsOne = Z1.isOne();
        ECFieldElement U2 = X2, S2 = L2;
        if (!Z1IsOne)
        {
            U2 = U2.multiply(Z1);
            S2 = S2.multiply(Z1);
        }

        boolean Z2IsOne = Z2.isOne();
        ECFieldElement U1 = X1, S1 = L1;
        if (!Z2IsOne)
        {
            U1 = U1.multiply(Z2);
            S1 = S1.multiply(Z2);
        }

        ECFieldElement A = S1.add(S2);
        ECFieldElement B = U1.add(U2);

        if (B.isZero())
        {
            if (A.isZero())
            {
                return twice();
            }

            return curve.getInfinity();
        }

        ECFieldElement X3, L3, Z3;
        if (X2.isZero())
        {
            // TODO This can probably be optimized quite a bit
            ECPoint p = this.normalize();
            X1 = p.getXCoord();
            ECFieldElement Y1 = p.getYCoord();

            ECFieldElement Y2 = L2;
            ECFieldElement L = Y1.add(Y2).divide(X1);

            X3 = L.square().add(L).add(X1);
            if (X3.isZero())
            {
                return new SecT233K1Point(curve, X3, curve.getB(), this.withCompression);
            }

            ECFieldElement Y3 = L.multiply(X1.add(X3)).add(X3).add(Y1);
            L3 = Y3.divide(X3).add(X3);
            Z3 = curve.fromBigInteger(ECConstants.ONE);
        }
        else
        {
            B = B.square();

            ECFieldElement AU1 = A.multiply(U1);
            ECFieldElement AU2 = A.multiply(U2);

            X3 = AU1.multiply(AU2);
            if (X3.isZero())
            {
                return new SecT233K1Point(curve, X3, curve.getB(), this.withCompression);
            }

            ECFieldElement ABZ2 = A.multiply(B);
            if (!Z2IsOne)
            {
                ABZ2 = ABZ2.multiply(Z2);
            }

            L3 = AU2.add(B).squarePlusProduct(ABZ2, L1.add(Z1));

            Z3 = ABZ2;
            if (!Z1IsOne)
            {
                Z3 = Z3.multiply(Z1);
            }
        }

        return new SecT233K1Point(curve, X3, L3, new ECFieldElement[]{ Z3 }, this.withCompression);
    }

    public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECCurve curve = this.getCurve();

        ECFieldElement X1 = this.x;
        if (X1.isZero())
        {
            // A point with X == 0 is it's own additive inverse
            return curve.getInfinity();
        }

        ECFieldElement L1 = this.y, Z1 = this.zs[0];

        boolean Z1IsOne = Z1.isOne();
        ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.square();
        ECFieldElement T;
        if (Z1IsOne)
        {
            T = L1.square().add(L1);
        }
        else
        {
            T = L1.add(Z1).multiply(L1);
        }

        if (T.isZero())
        {
            return new SecT233K1Point(curve, T, curve.getB(), withCompression);
        }

        ECFieldElement X3 = T.square();
        ECFieldElement Z3 = Z1IsOne ? T : T.multiply(Z1Sq);

        ECFieldElement t1 = L1.add(X1).square();
        ECFieldElement t2 = Z1IsOne ? Z1 : Z1Sq.square();
        ECFieldElement L3 = t1.add(T).add(Z1Sq).multiply(t1).add(t2).add(X3).add(Z3);

        return new SecT233K1Point(curve, X3, L3, new ECFieldElement[]{ Z3 }, this.withCompression);
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

        ECCurve curve = this.getCurve();

        ECFieldElement X1 = this.x;
        if (X1.isZero())
        {
            // A point with X == 0 is it's own additive inverse
            return b;
        }

        // NOTE: twicePlus() only optimized for lambda-affine argument
        ECFieldElement X2 = b.getRawXCoord(), Z2 = b.getZCoord(0);
        if (X2.isZero() || !Z2.isOne())
        {
            return twice().add(b);
        }

        ECFieldElement L1 = this.y, Z1 = this.zs[0];
        ECFieldElement L2 = b.getRawYCoord();

        ECFieldElement X1Sq = X1.square();
        ECFieldElement L1Sq = L1.square();
        ECFieldElement Z1Sq = Z1.square();
        ECFieldElement L1Z1 = L1.multiply(Z1);

        ECFieldElement T = L1Sq.add(L1Z1);
        ECFieldElement L2plus1 = L2.addOne();
        ECFieldElement A = L2plus1.multiply(Z1Sq).add(L1Sq).multiplyPlusProduct(T, X1Sq, Z1Sq);
        ECFieldElement X2Z1Sq = X2.multiply(Z1Sq);
        ECFieldElement B = X2Z1Sq.add(T).square();

        if (B.isZero())
        {
            if (A.isZero())
            {
                return b.twice();
            }

            return curve.getInfinity();
        }

        if (A.isZero())
        {
            return new SecT233K1Point(curve, A, curve.getB(), withCompression);
        }

        ECFieldElement X3 = A.square().multiply(X2Z1Sq);
        ECFieldElement Z3 = A.multiply(B).multiply(Z1Sq);
        ECFieldElement L3 = A.add(B).square().multiplyPlusProduct(T, L2plus1, Z3);

        return new SecT233K1Point(curve, X3, L3, new ECFieldElement[]{ Z3 }, this.withCompression);
    }

    public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECFieldElement X = this.x;
        if (X.isZero())
        {
            return this;
        }

        // L is actually Lambda (X + Y/X) here
        ECFieldElement L = this.y, Z = this.zs[0];
        return new SecT233K1Point(curve, X, L.add(Z), new ECFieldElement[]{ Z }, this.withCompression);
    }
}
