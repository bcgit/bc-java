package org.bouncycastle.math.ec.custom.gm;

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

public class SM2P256V1Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = SM2P256V1FieldElement.Q;

    private static final int SM2P256V1_DEFAULT_COORDS = COORD_JACOBIAN;
    private static final ECFieldElement[] SM2P256V1_AFFINE_ZS = new ECFieldElement[] { new SM2P256V1FieldElement(ECConstants.ONE) }; 

    protected SM2P256V1Point infinity;

    public SM2P256V1Curve()
    {
        super(q);

        this.infinity = new SM2P256V1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decodeStrict("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decodeStrict("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SM2P256V1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SM2P256V1Curve();
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
        return new SM2P256V1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SM2P256V1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SM2P256V1Point(this, x, y, zs);
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
                Nat256.copy(((SM2P256V1FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat256.copy(((SM2P256V1FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
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
                return createRawPoint(new SM2P256V1FieldElement(x), new SM2P256V1FieldElement(y), SM2P256V1_AFFINE_ZS);
            }
        };
    }

    public ECFieldElement randomFieldElement(SecureRandom r)
    {
        int[] x = Nat256.create();
        SM2P256V1Field.random(r, x);
        return new SM2P256V1FieldElement(x);
    }

    public ECFieldElement randomFieldElementMult(SecureRandom r)
    {
        int[] x = Nat256.create();
        SM2P256V1Field.randomMult(r, x);
        return new SM2P256V1FieldElement(x);
    }
}
