package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPoint.AbstractF2m;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat576;

public class SecT571R1Point extends AbstractF2m
{
    SecT571R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        super(curve, x, y);
    }

    SecT571R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        super(curve, x, y, zs);
    }

    protected ECPoint detach()
    {
        return new SecT571R1Point(null, getAffineXCoord(), getAffineYCoord());
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

        SecT571FieldElement X1 = (SecT571FieldElement)this.x;
        SecT571FieldElement X2 = (SecT571FieldElement)b.getRawXCoord();

        if (X1.isZero())
        {
            if (X2.isZero())
            {
                return curve.getInfinity();
            }

            return b.add(this);
        }

        SecT571FieldElement L1 = (SecT571FieldElement)this.y, Z1 = (SecT571FieldElement)this.zs[0];
        SecT571FieldElement L2 = (SecT571FieldElement)b.getRawYCoord(), Z2 = (SecT571FieldElement)b.getZCoord(0);

        long[] t1 = Nat576.create64();
        long[] t2 = Nat576.create64();
        long[] t3 = Nat576.create64();
        long[] t4 = Nat576.create64();

        long[] Z1Precomp = Z1.isOne() ? null : SecT571Field.precompMultiplicand(Z1.x);
        long[] U2, S2;
        if (Z1Precomp == null)
        {
            U2 = X2.x;
            S2 = L2.x;
        }
        else
        {
            SecT571Field.multiplyPrecomp(X2.x, Z1Precomp, U2 = t2);
            SecT571Field.multiplyPrecomp(L2.x, Z1Precomp, S2 = t4);
        }

        long[] Z2Precomp = Z2.isOne() ? null : SecT571Field.precompMultiplicand(Z2.x);
        long[] U1, S1;
        if (Z2Precomp == null)
        {
            U1 = X1.x;
            S1 = L1.x;
        }
        else
        {
            SecT571Field.multiplyPrecomp(X1.x, Z2Precomp, U1 = t1);
            SecT571Field.multiplyPrecomp(L1.x, Z2Precomp, S1 = t3);
        }

        long[] A = t3;
        SecT571Field.add(S1, S2, A);

        long[] B = t4;
        SecT571Field.add(U1, U2, B);

        if (Nat576.isZero64(B))
        {
            if (Nat576.isZero64(A))
            {
                return twice();
            }

            return curve.getInfinity();
        }

        SecT571FieldElement X3, L3, Z3;
        if (X2.isZero())
        {
            // TODO This can probably be optimized quite a bit
            ECPoint p = this.normalize();
            X1 = (SecT571FieldElement)p.getXCoord();
            ECFieldElement Y1 = p.getYCoord();

            ECFieldElement Y2 = L2;
            ECFieldElement L = Y1.add(Y2).divide(X1);

            X3 = (SecT571FieldElement)L.square().add(L).add(X1).addOne();
            if (X3.isZero())
            {
                return new SecT571R1Point(curve, X3, SecT571R1Curve.SecT571R1_B_SQRT);
            }

            ECFieldElement Y3 = L.multiply(X1.add(X3)).add(X3).add(Y1);
            L3 = (SecT571FieldElement)Y3.divide(X3).add(X3);
            Z3 = (SecT571FieldElement)curve.fromBigInteger(ECConstants.ONE);
        }
        else
        {
            SecT571Field.square(B, B);

            long[] APrecomp = SecT571Field.precompMultiplicand(A);

            long[] AU1 = t1;
            long[] AU2 = t2;

            SecT571Field.multiplyPrecomp(U1, APrecomp, AU1);
            SecT571Field.multiplyPrecomp(U2, APrecomp, AU2);

            X3 = new SecT571FieldElement(t1);
            SecT571Field.multiply(AU1, AU2, X3.x);

            if (X3.isZero())
            {
                return new SecT571R1Point(curve, X3, SecT571R1Curve.SecT571R1_B_SQRT);
            }

            Z3 = new SecT571FieldElement(t3);
            SecT571Field.multiplyPrecomp(B, APrecomp, Z3.x);

            if (Z2Precomp != null)
            {
                SecT571Field.multiplyPrecomp(Z3.x, Z2Precomp, Z3.x);
            }

            long[] tt = Nat576.createExt64();

            SecT571Field.add(AU2, B, t4);
            SecT571Field.squareAddToExt(t4, tt);

            SecT571Field.add(L1.x, Z1.x, t4);
            SecT571Field.multiplyAddToExt(t4, Z3.x, tt);

            L3 = new SecT571FieldElement(t4);
            SecT571Field.reduce(tt, L3.x);

            if (Z1Precomp != null)
            {
                SecT571Field.multiplyPrecomp(Z3.x, Z1Precomp, Z3.x);
            }
        }

        return new SecT571R1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
    }

    public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECCurve curve = this.getCurve();

        SecT571FieldElement X1 = (SecT571FieldElement)this.x;
        if (X1.isZero())
        {
            // A point with X == 0 is its own additive inverse
            return curve.getInfinity();
        }

        SecT571FieldElement L1 = (SecT571FieldElement)this.y, Z1 = (SecT571FieldElement)this.zs[0];

        long[] t1 = Nat576.create64();
        long[] t2 = Nat576.create64();

        long[] Z1Precomp = Z1.isOne() ? null : SecT571Field.precompMultiplicand(Z1.x);
        long[] L1Z1, Z1Sq;
        if (Z1Precomp == null)
        {
            L1Z1 = L1.x;
            Z1Sq = Z1.x;
        }
        else
        {
            SecT571Field.multiplyPrecomp(L1.x, Z1Precomp, L1Z1 = t1);
            SecT571Field.square(Z1.x, Z1Sq = t2);
        }

        long[] T = Nat576.create64();
        SecT571Field.square(L1.x, T);
        SecT571Field.addBothTo(L1Z1, Z1Sq, T);

        if (Nat576.isZero64(T))
        {
            return new SecT571R1Point(curve, new SecT571FieldElement(T), SecT571R1Curve.SecT571R1_B_SQRT);
        }

        long[] tt = Nat576.createExt64();
        SecT571Field.multiplyAddToExt(T, L1Z1, tt);

        SecT571FieldElement X3 = new SecT571FieldElement(t1);
        SecT571Field.square(T, X3.x);

        SecT571FieldElement Z3 = new SecT571FieldElement(T);
        if (Z1Precomp != null)
        {
            SecT571Field.multiply(Z3.x, Z1Sq, Z3.x);
        }

        long[] X1Z1;
        if (Z1Precomp == null)
        {
            X1Z1 = X1.x;
        }
        else
        {
            SecT571Field.multiplyPrecomp(X1.x, Z1Precomp, X1Z1 = t2);
        }

        SecT571Field.squareAddToExt(X1Z1, tt);
        SecT571Field.reduce(tt, t2);
        SecT571Field.addBothTo(X3.x, Z3.x, t2);
        SecT571FieldElement L3 = new SecT571FieldElement(t2);

        return new SecT571R1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
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

        SecT571FieldElement X1 = (SecT571FieldElement)this.x;
        if (X1.isZero())
        {
            // A point with X == 0 is its own additive inverse
            return b;
        }

        SecT571FieldElement X2 = (SecT571FieldElement)b.getRawXCoord(), Z2 = (SecT571FieldElement)b.getZCoord(0);
        if (X2.isZero() || !Z2.isOne())
        {
            return twice().add(b);
        }

        SecT571FieldElement L1 = (SecT571FieldElement)this.y, Z1 = (SecT571FieldElement)this.zs[0];
        SecT571FieldElement L2 = (SecT571FieldElement)b.getRawYCoord();

        long[] t1 = Nat576.create64();
        long[] t2 = Nat576.create64();
        long[] t3 = Nat576.create64();
        long[] t4 = Nat576.create64();

        long[] X1Sq = t1;
        SecT571Field.square(X1.x, X1Sq);

        long[] L1Sq = t2;
        SecT571Field.square(L1.x, L1Sq);

        long[] Z1Sq = t3;
        SecT571Field.square(Z1.x, Z1Sq);

        long[] L1Z1 = t4;
        SecT571Field.multiply(L1.x, Z1.x, L1Z1);

        long[] T = L1Z1;
        SecT571Field.addBothTo(Z1Sq, L1Sq, T);

        long[] Z1SqPrecomp = SecT571Field.precompMultiplicand(Z1Sq);

        long[] A = t3;
        SecT571Field.multiplyPrecomp(L2.x, Z1SqPrecomp, A);
        SecT571Field.add(A, L1Sq, A);

        long[] tt = Nat576.createExt64();
        SecT571Field.multiplyAddToExt(A, T, tt);
        SecT571Field.multiplyPrecompAddToExt(X1Sq, Z1SqPrecomp, tt);
        SecT571Field.reduce(tt, A);

        long[] X2Z1Sq = t1;
        SecT571Field.multiplyPrecomp(X2.x, Z1SqPrecomp, X2Z1Sq);

        long[] B = t2;
        SecT571Field.add(X2Z1Sq, T, B);
        SecT571Field.square(B, B);

        if (Nat576.isZero64(B))
        {
            if (Nat576.isZero64(A))
            {
                return b.twice();
            }

            return curve.getInfinity();
        }

        if (Nat576.isZero64(A))
        {
            return new SecT571R1Point(curve, new SecT571FieldElement(A), SecT571R1Curve.SecT571R1_B_SQRT);
        }

        SecT571FieldElement X3 = new SecT571FieldElement();
        SecT571Field.square(A, X3.x);
        SecT571Field.multiply(X3.x, X2Z1Sq, X3.x);

        SecT571FieldElement Z3 = new SecT571FieldElement(t1);
        SecT571Field.multiply(A, B, Z3.x);
        SecT571Field.multiplyPrecomp(Z3.x, Z1SqPrecomp, Z3.x);

        SecT571FieldElement L3 = new SecT571FieldElement(t2);
        SecT571Field.add(A, B, L3.x);
        SecT571Field.square(L3.x, L3.x);

        Nat.zero64(18, tt);
        SecT571Field.multiplyAddToExt(L3.x, T, tt);
        SecT571Field.addOne(L2.x, t4);
        SecT571Field.multiplyAddToExt(t4, Z3.x, tt);
        SecT571Field.reduce(tt, L3.x);

        return new SecT571R1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
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
        return new SecT571R1Point(curve, X, L.add(Z), new ECFieldElement[]{ Z });
    }
}
