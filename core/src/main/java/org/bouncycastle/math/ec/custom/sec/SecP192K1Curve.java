package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.encoders.Hex;

public class SecP192K1Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = SecP192K1FieldElement.Q;

    private static final int SECP192K1_DEFAULT_COORDS = COORD_JACOBIAN;
    private static final ECFieldElement[] SECP192K1_AFFINE_ZS = new ECFieldElement[] { new SecP192K1FieldElement(ECConstants.ONE) }; 

    protected SecP192K1Point infinity;

    public SecP192K1Curve()
    {
        super(q);

        this.infinity = new SecP192K1Point(this, null, null);

        this.a = fromBigInteger(ECConstants.ZERO);
        this.b = fromBigInteger(BigInteger.valueOf(3));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SECP192K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP192K1Curve();
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
        return new SecP192K1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecP192K1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecP192K1Point(this, x, y, zs);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_INTS = 6;

        final int[] table = new int[len * FE_INTS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat192.copy(((SecP192K1FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat192.copy(((SecP192K1FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
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
                int[] x = Nat192.create(), y = Nat192.create();
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

                return createPoint(x, y);
            }

            public ECPoint lookupVar(int index)
            {
                int[] x = Nat192.create(), y = Nat192.create();
                int pos = index * FE_INTS * 2;

                for (int j = 0; j < FE_INTS; ++j)
                {
                    x[j] = table[pos + j];
                    y[j] = table[pos + FE_INTS + j];
                }

                return createPoint(x, y);
            }

            private ECPoint createPoint(int[] x, int[] y)
            {
                return createRawPoint(new SecP192K1FieldElement(x), new SecP192K1FieldElement(y), SECP192K1_AFFINE_ZS);
            }
        };
    }

    public ECFieldElement randomFieldElement(SecureRandom r)
    {
        int[] x = Nat192.create();
        SecP192K1Field.random(r, x);
        return new SecP192K1FieldElement(x);
    }

    public ECFieldElement randomFieldElementMult(SecureRandom r)
    {
        int[] x = Nat192.create();
        SecP192K1Field.randomMult(r, x);
        return new SecP192K1FieldElement(x);
    }
}
