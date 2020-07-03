package org.bouncycastle.math.ec.custom.sec;

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

public class SecP256R1Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = SecP256R1FieldElement.Q;

    private static final int SECP256R1_DEFAULT_COORDS = COORD_JACOBIAN;
    private static final ECFieldElement[] SECP256R1_AFFINE_ZS = new ECFieldElement[] { new SecP256R1FieldElement(ECConstants.ONE) }; 

    protected SecP256R1Point infinity;

    public SecP256R1Curve()
    {
        super(q);

        this.infinity = new SecP256R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decodeStrict("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decodeStrict("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SECP256R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP256R1Curve();
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
        return new SecP256R1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SecP256R1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SecP256R1Point(this, x, y, zs);
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
                Nat256.copy(((SecP256R1FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat256.copy(((SecP256R1FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
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
                return createRawPoint(new SecP256R1FieldElement(x), new SecP256R1FieldElement(y), SECP256R1_AFFINE_ZS);
            }
        };
    }

    public ECFieldElement randomFieldElement(SecureRandom r)
    {
        int[] x = Nat256.create();
        SecP256R1Field.random(r, x);
        return new SecP256R1FieldElement(x);
    }

    public ECFieldElement randomFieldElementMult(SecureRandom r)
    {
        int[] x = Nat256.create();
        SecP256R1Field.randomMult(r, x);
        return new SecP256R1FieldElement(x);
    }
}
