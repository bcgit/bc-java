package com.github.gv2011.bcasn.math.ec.custom.sec;

import java.math.BigInteger;

import com.github.gv2011.bcasn.math.ec.ECConstants;
import com.github.gv2011.bcasn.math.ec.ECCurve;
import com.github.gv2011.bcasn.math.ec.ECFieldElement;
import com.github.gv2011.bcasn.math.ec.ECPoint;
import com.github.gv2011.bcasn.util.encoders.Hex;

public class SecP224K1Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = new BigInteger(1,
        Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D"));

    private static final int SECP224K1_DEFAULT_COORDS = COORD_JACOBIAN;

    protected SecP224K1Point infinity;

    public SecP224K1Curve()
    {
        super(q);

        this.infinity = new SecP224K1Point(this, null, null);

        this.a = fromBigInteger(ECConstants.ZERO);
        this.b = fromBigInteger(BigInteger.valueOf(5));
        this.order = new BigInteger(1, Hex.decode("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7"));
        this.cofactor = BigInteger.valueOf(1);
        this.coord = SECP224K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP224K1Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_JACOBIAN:
            return true;
        default:
            return false;
        }
    }

    public BigInteger getQ()
    {
        return q;
    }

    public int getFieldSize()
    {
        return q.bitLength();
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecP224K1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecP224K1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecP224K1Point(this, x, y, zs, withCompression);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }
}
