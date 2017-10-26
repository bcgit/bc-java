package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat160;
import org.bouncycastle.util.encoders.Hex;

public class SecP160R1Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = new BigInteger(1,
        Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF"));

    private static final int SecP160R1_DEFAULT_COORDS = COORD_JACOBIAN;

    protected SecP160R1Point infinity;

    public SecP160R1Curve()
    {
        super(q);

        this.infinity = new SecP160R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decode("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45")));
        this.order = new BigInteger(1, Hex.decode("0100000000000000000001F4C8F927AED3CA752257"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SecP160R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP160R1Curve();
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
        return new SecP160R1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecP160R1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecP160R1Point(this, x, y, zs, withCompression);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_INTS = 5;

        final int[] table = new int[len * FE_INTS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat160.copy(((SecP160R1FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat160.copy(((SecP160R1FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
            }
        }

        return new ECLookupTable()
        {
            public int getSize()
            {
                return len;
            }

            public ECPoint lookup(int index)
            {
                int[] x = Nat160.create(), y = Nat160.create();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    int MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_INTS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_INTS + j] & MASK;
                    }

                    pos += (FE_INTS * 2);
                }

                return createRawPoint(new SecP160R1FieldElement(x), new SecP160R1FieldElement(y), false);
            }
        };
    }
}
