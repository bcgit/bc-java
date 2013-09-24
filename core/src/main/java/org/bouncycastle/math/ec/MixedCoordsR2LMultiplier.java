package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class MixedCoordsR2LMultiplier implements ECMultiplier
{
    protected int additionCoord, doublingCoord;

    public MixedCoordsR2LMultiplier()
    {
        this(ECCurve.COORD_JACOBIAN, ECCurve.COORD_JACOBIAN_MODIFIED);
    }

    public MixedCoordsR2LMultiplier(int additionCoord, int doublingCoord)
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

        byte[] wnaf = WNafUtil.generateNaf(k);

        for (int i = 0; i < wnaf.length; ++i)
        {
            int wi = wnaf[i];
            if (wi != 0)
            {
                ECPoint Tj = curveAdd.importPoint(Td);
                if (wi < 0)
                {
                    Tj = Tj.negate();
                }

                Ra = Ra.add(Tj);
            }
            Td = Td.twice();
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
