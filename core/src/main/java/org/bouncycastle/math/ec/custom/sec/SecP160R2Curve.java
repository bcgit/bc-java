package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

public class SecP160R2Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = new BigInteger(1,
        Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73"));

    private static final int SecP160R2_DEFAULT_COORDS = COORD_JACOBIAN;

    protected SecP160R2Point infinity;

    public SecP160R2Curve()
    {
        super(q);

        this.infinity = new SecP160R2Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decode("B4E134D3FB59EB8BAB57274904664D5AF50388BA")));
        this.order = new BigInteger(1, Hex.decode("0100000000000000000000351EE786A818F3A1A16B"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SecP160R2_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP160R2Curve();
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
        return new SecP160R2FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecP160R2Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecP160R2Point(this, x, y, zs, withCompression);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }
}
