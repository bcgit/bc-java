package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.encoders.Hex;

public class SecT193R2Curve extends AbstractF2m
{
    private static final int SECT193R2_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;
    private static final ECFieldElement[] SECT193R2_AFFINE_ZS = new ECFieldElement[] { new SecT193FieldElement(ECConstants.ONE) }; 

    protected SecT193R2Point infinity;

    public SecT193R2Curve()
    {
        super(193, 15, 0, 0);

        this.infinity = new SecT193R2Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE")));
        this.order = new BigInteger(1, Hex.decodeStrict("010000000000000000000000015AAB561B005413CCD4EE99D5"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SECT193R2_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT193R2Curve();
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
        return 193;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT193FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecT193R2Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecT193R2Point(this, x, y, zs);
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
        return 193;
    }

    public boolean isTrinomial()
    {
        return true;
    }

    public int getK1()
    {
        return 15;
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
                Nat256.copy64(((SecT193FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_LONGS;
                Nat256.copy64(((SecT193FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_LONGS;
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

                return createPoint(x, y);
            }

            public ECPoint lookupVar(int index)
            {
                long[] x = Nat256.create64(), y = Nat256.create64();
                int pos = index * FE_LONGS * 2;

                for (int j = 0; j < FE_LONGS; ++j)
                {
                    x[j] ^= table[pos + j];
                    y[j] ^= table[pos + FE_LONGS + j];
                }

                return createPoint(x, y);
            }

            private ECPoint createPoint(long[] x, long[] y)
            {
                return createRawPoint(new SecT193FieldElement(x), new SecT193FieldElement(y), SECT193R2_AFFINE_ZS);
            }
        };
    }
}
