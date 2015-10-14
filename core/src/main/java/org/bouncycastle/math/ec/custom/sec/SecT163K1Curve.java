package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WTauNafMultiplier;
import org.bouncycastle.util.encoders.Hex;

public class SecT163K1Curve extends AbstractF2m
{
    private static final int SecT163K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT163K1Point infinity;

    public SecT163K1Curve()
    {
        super(163, 3, 6, 7);

        this.infinity = new SecT163K1Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(1));
        this.b = this.a;
        this.order = new BigInteger(1, Hex.decode("04000000000000000000020108A2E0CC0D99F8A5EF"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT163K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT163K1Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_LAMBDA_PROJECTIVE:
            return true;
        default:
            return false;
        }
    }

    protected ECMultiplier createDefaultMultiplier()
    {
        return new WTauNafMultiplier();
    }

    public int getFieldSize()
    {
        return 163;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT163FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT163K1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT163K1Point(this, x, y, zs, withCompression);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public boolean isKoblitz()
    {
        return true;
    }

    public int getM()
    {
        return 163;
    }

    public boolean isTrinomial()
    {
        return false;
    }

    public int getK1()
    {
        return 3;
    }

    public int getK2()
    {
        return 6;
    }

    public int getK3()
    {
        return 7;
    }
}
