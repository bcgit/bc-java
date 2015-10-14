package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class SecT163R2Curve extends AbstractF2m
{
    private static final int SecT163R2_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT163R2Point infinity;

    public SecT163R2Curve()
    {
        super(163, 3, 6, 7);

        this.infinity = new SecT163R2Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(1));
        this.b = fromBigInteger(new BigInteger(1, Hex.decode("020A601907B8C953CA1481EB10512F78744A3205FD")));
        this.order = new BigInteger(1, Hex.decode("040000000000000000000292FE77E70C12A4234C33"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT163R2_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT163R2Curve();
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
        return 163;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT163FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT163R2Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT163R2Point(this, x, y, zs, withCompression);
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
