package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class SecT571R1Curve extends AbstractF2m
{
    private static final int SecT571R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT571R1Point infinity;

    static final SecT571FieldElement SecT571R1_B = new SecT571FieldElement(
        new BigInteger(1, Hex.decode("02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A")));
    static final SecT571FieldElement SecT571R1_B_SQRT = (SecT571FieldElement)SecT571R1_B.sqrt();

    public SecT571R1Curve()
    {
        super(571, 2, 5, 10);

        this.infinity = new SecT571R1Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(1));
        this.b = SecT571R1_B;
        this.order = new BigInteger(1, Hex.decode("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT571R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT571R1Curve();
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

    public int getFieldSize()
    {
        return 571;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT571FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT571R1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT571R1Point(this, x, y, zs, withCompression);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public boolean isKoblitz()
    {
        return false;
    }

    public int getM()
    {
        return 571;
    }

    public boolean isTrinomial()
    {
        return false;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 5;
    }

    public int getK3()
    {
        return 10;
    }
}
