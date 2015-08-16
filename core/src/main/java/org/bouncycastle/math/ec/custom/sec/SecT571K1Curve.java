package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.util.Random;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.AbstractF2m;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WTauNafMultiplier;
import org.bouncycastle.util.encoders.Hex;

public class SecT571K1Curve extends AbstractF2m
{
    private static final int SecT571K1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT571K1Point infinity;

    public SecT571K1Curve()
    {
        super(571, 2, 5, 10);

        this.infinity = new SecT571K1Point(this, null, null);

        this.a = fromBigInteger(BigInteger.valueOf(0));
        this.b = fromBigInteger(BigInteger.valueOf(1));
        this.order = new BigInteger(1, Hex.decode("020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001"));
        this.cofactor = BigInteger.valueOf(4);

        this.coord = SecT571K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT571K1Curve();
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
        return 571;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT571FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT571K1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT571K1Point(this, x, y, zs, withCompression);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public boolean isKoblitz()
    {
        return true;
    }

    /**
     * Decompresses a compressed point P = (xp, yp) (X9.62 s 4.2.2).
     *
     * @param yTilde
     *            ~yp, an indication bit for the decompression of yp.
     * @param X1
     *            The field element xp.
     * @return the decompressed point.
     */
    protected ECPoint decompressPoint(int yTilde, BigInteger X1)
    {
        ECFieldElement x = fromBigInteger(X1), y = null;
        if (x.isZero())
        {
            y = b.sqrt();
        }
        else
        {
            ECFieldElement beta = x.square().invert().multiply(b).add(a).add(x);
            ECFieldElement z = solveQuadraticEquation(beta);
            if (z != null)
            {
                if (z.testBitZero() != (yTilde == 1))
                {
                    z = z.addOne();
                }

                switch (this.getCoordinateSystem())
                {
                case COORD_LAMBDA_AFFINE:
                case COORD_LAMBDA_PROJECTIVE:
                {
                    y = z.add(x);
                    break;
                }
                default:
                {
                    y = z.multiply(x);
                    break;
                }
                }
            }
        }

        if (y == null)
        {
            throw new IllegalArgumentException("Invalid point compression");
        }

        return this.createRawPoint(x, y, true);
    }

    /**
     * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
     * D.1.6) The other solution is <code>z + 1</code>.
     *
     * @param beta
     *            The value to solve the quadratic equation for.
     * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
     *         <code>null</code> if no solution exists.
     */
    private ECFieldElement solveQuadraticEquation(ECFieldElement beta)
    {
        if (beta.isZero())
        {
            return beta;
        }

        ECFieldElement zeroElement = fromBigInteger(ECConstants.ZERO);

        ECFieldElement z = null;
        ECFieldElement gamma = null;

        Random rand = new Random();
        do
        {
            ECFieldElement t = fromBigInteger(new BigInteger(571, rand));
            z = zeroElement;
            ECFieldElement w = beta;
            for (int i = 1; i < 571; i++)
            {
                ECFieldElement w2 = w.square();
                z = z.square().add(w2.multiply(t));
                w = w2.add(beta);
            }
            if (!w.isZero())
            {
                return null;
            }
            gamma = z.square().add(z);
        }
        while (gamma.isZero());

        return z;
    }

    public int getM()
    {
        return 571;
    }

    public boolean isTrinomial()
    {
        return false;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 5;
    }

    public int getK3()
    {
        return 10;
    }
}
