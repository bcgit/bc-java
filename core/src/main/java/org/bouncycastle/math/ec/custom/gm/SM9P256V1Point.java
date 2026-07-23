package org.bouncycastle.math.ec.custom.gm;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Jacobian-coordinate point of the SM9 G1 curve y^2 = x^3 + 5 (a = 0) over
 * {@link SM9P256V1Field}.
 * <p>
 * The group law is the standard a=0 Jacobian addition (add-2007-bl) and doubling
 * (dbl-2009-l), written in terms of the {@link ECFieldElement} operations so it is
 * correct over the Montgomery-form field. (It does not use the Solinas-specific
 * int[]-level fused reductions that {@link SM2P256V1Point} relies on, which are
 * not valid for a Montgomery representation.)
 */
public class SM9P256V1Point extends ECPoint.AbstractFp
{
    SM9P256V1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        super(curve, x, y);
    }

    SM9P256V1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        super(curve, x, y, zs);
    }

    protected ECPoint detach()
    {
        return new SM9P256V1Point(null, getAffineXCoord(), getAffineYCoord());
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
        if (this == b)
        {
            return twice();
        }

        ECCurve curve = getCurve();
        ECFieldElement X1 = this.x, Y1 = this.y, Z1 = this.zs[0];
        ECFieldElement X2 = b.getXCoord(), Y2 = b.getYCoord(), Z2 = b.getZCoord(0);

        ECFieldElement Z1Z1 = Z1.square();
        ECFieldElement Z2Z2 = Z2.square();
        ECFieldElement U1 = X1.multiply(Z2Z2);
        ECFieldElement U2 = X2.multiply(Z1Z1);
        ECFieldElement S1 = Y1.multiply(Z2).multiply(Z2Z2);
        ECFieldElement S2 = Y2.multiply(Z1).multiply(Z1Z1);
        ECFieldElement H = U2.subtract(U1);
        ECFieldElement rr = S2.subtract(S1);

        if (H.isZero())
        {
            if (rr.isZero())
            {
                return twice();               // this == b
            }
            return curve.getInfinity();       // this == -b
        }

        ECFieldElement twoH = H.add(H);
        ECFieldElement I = twoH.square();
        ECFieldElement J = H.multiply(I);
        ECFieldElement r = rr.add(rr);
        ECFieldElement V = U1.multiply(I);

        ECFieldElement X3 = r.square().subtract(J).subtract(V.add(V));
        ECFieldElement S1J = S1.multiply(J);
        ECFieldElement Y3 = r.multiply(V.subtract(X3)).subtract(S1J.add(S1J));
        ECFieldElement Z3 = Z1.add(Z2).square().subtract(Z1Z1).subtract(Z2Z2).multiply(H);

        return new SM9P256V1Point(curve, X3, Y3, new ECFieldElement[]{ Z3 });
    }

    public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECCurve curve = getCurve();
        ECFieldElement Y1 = this.y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        ECFieldElement X1 = this.x, Z1 = this.zs[0];

        ECFieldElement XX = X1.square();
        ECFieldElement YY = Y1.square();
        ECFieldElement YYYY = YY.square();
        ECFieldElement ZZ = Z1.square();
        ECFieldElement t = X1.add(YY).square().subtract(XX).subtract(YYYY);
        ECFieldElement S = t.add(t);                    // 4 * X1 * YY
        ECFieldElement M = XX.add(XX).add(XX);          // 3 * XX  (a = 0)

        ECFieldElement X3 = M.square().subtract(S).subtract(S);
        ECFieldElement eightYYYY = YYYY.add(YYYY);
        eightYYYY = eightYYYY.add(eightYYYY);
        eightYYYY = eightYYYY.add(eightYYYY);
        ECFieldElement Y3 = M.multiply(S.subtract(X3)).subtract(eightYYYY);
        ECFieldElement Z3 = Y1.add(Z1).square().subtract(YY).subtract(ZZ);

        return new SM9P256V1Point(curve, X3, Y3, new ECFieldElement[]{ Z3 });
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
        if (this.y.isZero())
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
        return twice().add(this);
    }

    public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }
        return new SM9P256V1Point(curve, this.x, this.y.negate(), this.zs);
    }
}
