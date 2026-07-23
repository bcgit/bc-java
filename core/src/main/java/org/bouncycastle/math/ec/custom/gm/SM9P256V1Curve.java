package org.bouncycastle.math.ec.custom.gm;

import java.math.BigInteger;

import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat256;

/**
 * The SM9 G1 curve E: y^2 = x^3 + 5 (a = 0) over the 256-bit Barreto-Naehrig base
 * field F_q (GM/T 0044.5-2016), backed by the constant-time Montgomery field
 * {@link SM9P256V1Field}. This is the same custom-curve pattern as
 * {@link SM2P256V1Curve} but for a general (non-Solinas) prime; it is used only as
 * the G1 of the SM9 identity-based schemes and supports uncompressed points only.
 */
public class SM9P256V1Curve extends ECCurve.AbstractFp
{
    public static final BigInteger q = SM9P256V1FieldElement.Q;

    private static final int SM9P256V1_DEFAULT_COORDS = COORD_JACOBIAN;
    private static final ECFieldElement[] SM9P256V1_AFFINE_ZS =
        new ECFieldElement[]{ new SM9P256V1FieldElement(ECConstants.ONE) };

    protected SM9P256V1Point infinity;

    public SM9P256V1Curve()
    {
        super(q);

        this.infinity = new SM9P256V1Point(this, null, null);

        this.a = fromBigInteger(ECConstants.ZERO);
        this.b = fromBigInteger(BigInteger.valueOf(5));
        this.order = new BigInteger(1, org.bouncycastle.util.encoders.Hex.decodeStrict(
            "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SM9P256V1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SM9P256V1Curve();
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
        return new SM9P256V1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y)
    {
        return new SM9P256V1Point(this, x, y);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        return new SM9P256V1Point(this, x, y, zs);
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
                Nat256.copy(((SM9P256V1FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_INTS;
                Nat256.copy(((SM9P256V1FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_INTS;
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
                return createRawPoint(new SM9P256V1FieldElement(x), new SM9P256V1FieldElement(y), SM9P256V1_AFFINE_ZS);
            }
        };
    }
}
