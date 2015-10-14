package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class SecT283R1Curve extends AbstractF2m
{
    private static final int SecT283R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT283R1Point infinity;

    public SecT283R1Curve()
    {
        super(283, 5, 7, 12);

        this.infinity = new SecT283R1Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(1));
        this.b = fromBigInteger(new BigInteger(1, Hex.decode("027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5")));
        this.order = new BigInteger(1, Hex.decode("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT283R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT283R1Curve();
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
        return 283;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT283FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT283R1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT283R1Point(this, x, y, zs, withCompression);
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
        return 283;
    }

    public boolean isTrinomial()
    {
        return false;
    }

    public int getK1()
    {
        return 5;
    }

    public int getK2()
    {
        return 7;
    }

    public int getK3()
    {
        return 12;
    }
}
