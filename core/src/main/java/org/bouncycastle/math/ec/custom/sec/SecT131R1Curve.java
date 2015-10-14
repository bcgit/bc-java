package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class SecT131R1Curve extends AbstractF2m
{
    private static final int SecT131R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT131R1Point infinity;

    public SecT131R1Curve()
    {
        super(131, 2, 3, 8);

        this.infinity = new SecT131R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1, Hex.decode("07A11B09A76B562144418FF3FF8C2570B8")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decode("0217C05610884B63B9C6C7291678F9D341")));
        this.order = new BigInteger(1, Hex.decode("0400000000000000023123953A9464B54D"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT131R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT131R1Curve();
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
        return 131;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT131FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT131R1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT131R1Point(this, x, y, zs, withCompression);
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
        return 131;
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
        return 3;
    }

    public int getK3()
    {
        return 8;
    }
}
