package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WTauNafMultiplier;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.encoders.Hex;

public class SecT233K1Curve extends AbstractF2m
{
    private static final int SecT233K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT233K1Point infinity;

    public SecT233K1Curve()
    {
        super(233, 74, 0, 0);

        this.infinity = new SecT233K1Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(0));
        this.b = fromBigInteger(BigInteger.valueOf(1));
        this.order = new BigInteger(1, Hex.decode("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF"));
        this.cofactor = BigInteger.valueOf(4);

        this.coord = SecT233K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT233K1Curve();
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
        return 233;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT233FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT233K1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT233K1Point(this, x, y, zs, withCompression);
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
        return 233;
    }

    public boolean isTrinomial()
    {
        return true;
    }

    public int getK1()
    {
        return 74;
    }

    public int getK2()
    {
        return 0;
    }

    public int getK3()
    {
        return 0;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_LONGS = 4;

        final long[] table = new long[len * FE_LONGS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat256.copy64(((SecT233FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_LONGS;
                Nat256.copy64(((SecT233FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_LONGS;
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
                long[] x = Nat256.create64(), y = Nat256.create64();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    long MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_LONGS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_LONGS + j] & MASK;
                    }

                    pos += (FE_LONGS * 2);
                }

                return createRawPoint(new SecT233FieldElement(x), new SecT233FieldElement(y), false);
            }
        };
    }
}
