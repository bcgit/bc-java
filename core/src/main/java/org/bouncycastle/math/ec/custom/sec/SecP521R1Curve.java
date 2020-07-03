package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.encoders.Hex;

public class SecP521R1Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = SecP521R1FieldElement.Q;

    private static final int SECP521R1_DEFAULT_COORDS = COORD_JACOBIAN;
    private static final ECFieldElement[] SECP521R1_AFFINE_ZS = new ECFieldElement[] { new SecP521R1FieldElement(ECConstants.ONE) }; 

    protected SecP521R1Point infinity;

    public SecP521R1Curve()
    {
        super(q);

        this.infinity = new SecP521R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decodeStrict("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decodeStrict("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00")));
        this.order = new BigInteger(1, Hex.decodeStrict("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SECP521R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP521R1Curve();
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
        return new SecP521R1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecP521R1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecP521R1Point(this, x, y, zs);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_INTS = 17;

        final int[] table = new int[len * FE_INTS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat.copy(FE_INTS, ((SecP521R1FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat.copy(FE_INTS, ((SecP521R1FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
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
                int[] x = Nat.create(FE_INTS), y = Nat.create(FE_INTS);
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
                int[] x = Nat.create(FE_INTS), y = Nat.create(FE_INTS);
                int pos = index * FE_INTS * 2;

                for (int j = 0; j < FE_INTS; ++j)
                {
                    x[j] ^= table[pos + j];
                    y[j] ^= table[pos + FE_INTS + j];
                }

                return createPoint(x, y);
            }

            private ECPoint createPoint(int[] x, int[] y)
            {
                return createRawPoint(new SecP521R1FieldElement(x), new SecP521R1FieldElement(y), SECP521R1_AFFINE_ZS);
            }
        };
    }

    public ECFieldElement randomFieldElement(SecureRandom r)
    {
        int[] x = Nat.create(17);
        SecP521R1Field.random(r, x);
        return new SecP521R1FieldElement(x);
    }

    public ECFieldElement randomFieldElementMult(SecureRandom r)
    {
        int[] x = Nat.create(17);
        SecP521R1Field.randomMult(r, x);
        return new SecP521R1FieldElement(x);
    }
}
