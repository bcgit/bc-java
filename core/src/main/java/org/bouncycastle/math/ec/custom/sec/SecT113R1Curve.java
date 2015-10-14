package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class SecT113R1Curve extends AbstractF2m
{
    private static final int SecT113R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT113R1Point infinity;

    public SecT113R1Curve()
    {
        super(113, 9, 0, 0);

        this.infinity = new SecT113R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1, Hex.decode("003088250CA6E7C7FE649CE85820F7")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decode("00E8BEE4D3E2260744188BE0E9C723")));
        this.order = new BigInteger(1, Hex.decode("0100000000000000D9CCEC8A39E56F"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT113R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT113R1Curve();
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
        return 113;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT113FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT113R1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT113R1Point(this, x, y, zs, withCompression);
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
        return 113;
    }

    public boolean isTrinomial()
    {
        return true;
    }

    public int getK1()
    {
        return 9;
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
