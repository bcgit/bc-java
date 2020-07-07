package org.bouncycastle.math.ec.custom.djb;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.encoders.Hex;

public class Curve25519 extends ECCurve.AbstractFp
{
    public static final BigInteger q = Curve25519FieldElement.Q;

    private static final BigInteger C_a = new BigInteger(1, Hex.decodeStrict("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144"));
    private static final BigInteger C_b = new BigInteger(1, Hex.decodeStrict("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864"));

    private static final int CURVE25519_DEFAULT_COORDS = COORD_JACOBIAN_MODIFIED;
    private static final ECFieldElement[] CURVE25519_AFFINE_ZS = new ECFieldElement[] {
        new Curve25519FieldElement(ECConstants.ONE), new Curve25519FieldElement(C_a) }; 

    protected Curve25519Point infinity;

    public Curve25519()
    {
        super(q);

        this.infinity = new Curve25519Point(this, null, null);

        this.a = fromBigInteger(C_a);
        this.b = fromBigInteger(C_b);
        this.order = new BigInteger(1, Hex.decodeStrict("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"));
        this.cofactor = BigInteger.valueOf(8);

        this.coord = CURVE25519_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new Curve25519();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_JACOBIAN_MODIFIED:
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
        return new Curve25519FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new Curve25519Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new Curve25519Point(this, x, y, zs);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_INTS = 8;

        final int[] table = new int[len * FE_INTS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat256.copy(((Curve25519FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat256.copy(((Curve25519FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
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
                int[] x = Nat256.create(), y = Nat256.create();
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
                int[] x = Nat256.create(), y = Nat256.create();
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
                return createRawPoint(new Curve25519FieldElement(x), new Curve25519FieldElement(y), CURVE25519_AFFINE_ZS);
            }
        };
    }

    public ECFieldElement randomFieldElement(SecureRandom r)
    {
        int[] x = Nat256.create();
        Curve25519Field.random(r, x);
        return new Curve25519FieldElement(x);
    }

    public ECFieldElement randomFieldElementMult(SecureRandom r)
    {
        int[] x = Nat256.create();
        Curve25519Field.randomMult(r, x);
        return new Curve25519FieldElement(x);
    }
}
