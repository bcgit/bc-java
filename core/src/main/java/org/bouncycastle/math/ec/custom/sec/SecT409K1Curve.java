package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WTauNafMultiplier;
import org.bouncycastle.util.encoders.Hex;

public class SecT409K1Curve extends AbstractF2m
{
    private static final int SecT409K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT409K1Point infinity;

    public SecT409K1Curve()
    {
        super(409, 87, 0, 0);

        this.infinity = new SecT409K1Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(0));
        this.b = fromBigInteger(BigInteger.valueOf(1));
        this.order = new BigInteger(1, Hex.decode("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF"));
        this.cofactor = BigInteger.valueOf(4);

        this.coord = SecT409K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT409K1Curve();
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
        return 409;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT409FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT409K1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT409K1Point(this, x, y, zs, withCompression);
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
        return 409;
    }

    public boolean isTrinomial()
    {
        return true;
    }

    public int getK1()
    {
        return 87;
    }

    public int getK2()
    {
        return 0;
    }

    public int getK3()
    {
        return 0;
    }
}
