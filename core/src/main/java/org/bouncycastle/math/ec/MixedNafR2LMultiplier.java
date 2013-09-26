package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the NAF (Non-Adjacent Form) multiplication algorithm (right-to-left) using
 * mixed coordinates.
 */
public class MixedNafR2LMultiplier implements ECMultiplier
{
    protected int additionCoord, doublingCoord;

    /**
     * By default, addition will be done in Jacobian coordinates, and doubling will be done in
     * Modified Jacobian coordinates (independent of the original coordinate system of each point).
     */
    public MixedNafR2LMultiplier()
    {
        this(ECCurve.COORD_JACOBIAN, ECCurve.COORD_JACOBIAN_MODIFIED);
    }

    public MixedNafR2LMultiplier(int additionCoord, int doublingCoord)
    {
        this.additionCoord = additionCoord;
        this.doublingCoord = doublingCoord;
    }

    public ECPoint multiply(ECPoint p, BigInteger k, PreCompInfo preCompInfo)
    {
        if (k.signum() < 0)
        {
            throw new IllegalArgumentException("'k' cannot be negative");
        }
        if (k.signum() == 0)
        {
            return p.getCurve().getInfinity();
        }

        ECCurve curveAdd = configureCurve(p.getCurve(), additionCoord);
        ECCurve curveDouble = configureCurve(p.getCurve(), doublingCoord);

        ECPoint Ra = curveAdd.getInfinity();
        ECPoint Td = curveDouble.importPoint(p);

        int[] naf = WNafUtil.generateCompactNaf(k);
        int zeroes = 0;

        for (int i = 0; i < naf.length; ++i)
        {
            int ni = naf[i];
            int digit = ni >> 16;
            zeroes += ni & 0xFFFF;

            Td = Td.timesPow2(zeroes);

            ECPoint Tj = curveAdd.importPoint(Td);
            if (digit < 0)
            {
                Tj = Tj.negate();
            }

            Ra = Ra.add(Tj);

            zeroes = 1;
        }

        return p.getCurve().importPoint(Ra);
    }

    protected ECCurve configureCurve(ECCurve c, int coord)
    {
        if (c.getCoordinateSystem() == coord)
        {
            return c;
        }

        if (!c.supportsCoordinateSystem(coord))
        {
            throw new IllegalArgumentException("Coordinate system " + coord + " not supported by this curve");
        }

        return c.configure().setCoordinateSystem(coord).create();
    }
}
