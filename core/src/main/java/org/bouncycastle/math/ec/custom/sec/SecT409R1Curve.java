package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat448;
import org.bouncycastle.util.encoders.Hex;

public class SecT409R1Curve extends AbstractF2m
{
    private static final int SECT409R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;
    private static final ECFieldElement[] SECT409R1_AFFINE_ZS = new ECFieldElement[] { new SecT409FieldElement(ECConstants.ONE) }; 

    protected SecT409R1Point infinity;

    public SecT409R1Curve()
    {
        super(409, 87, 0, 0);

        this.infinity = new SecT409R1Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(1));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F")));
        this.order = new BigInteger(1, Hex.decodeStrict("010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SECT409R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT409R1Curve();
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
        return 409;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT409FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecT409R1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecT409R1Point(this, x, y, zs);
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

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_LONGS = 7;

        final long[] table = new long[len * FE_LONGS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat448.copy64(((SecT409FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_LONGS;
                Nat448.copy64(((SecT409FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_LONGS;
            }
        }

        return new AbstractECLookupTable()
        {
            public int getSize()
            {
                return len;
            }

            public ECPoint lookup(int index)
            {
                long[] x = Nat448.create64(), y = Nat448.create64();
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

                return createPoint(x, y);
            }

            public ECPoint lookupVar(int index)
            {
                long[] x = Nat448.create64(), y = Nat448.create64();
                int pos = index * FE_LONGS * 2;

                for (int j = 0; j < FE_LONGS; ++j)
                {
                    x[j] = table[pos + j];
                    y[j] = table[pos + FE_LONGS + j];
                }

                return createPoint(x, y);
            }

            private ECPoint createPoint(long[] x, long[] y)
            {
                return createRawPoint(new SecT409FieldElement(x), new SecT409FieldElement(y), SECT409R1_AFFINE_ZS);
            }
        };
    }
}
