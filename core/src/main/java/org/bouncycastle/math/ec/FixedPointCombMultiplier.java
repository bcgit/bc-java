package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class FixedPointCombMultiplier extends AbstractECMultiplier
{
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        int width = 4;

        FixedPointPreCompInfo info = FixedPointUtil.precompute(p, width);
        ECPoint[] lookupTable = info.getPreComp();

        ECCurve c = p.getCurve();
        int d = (c.getOrder().bitLength() + width - 1) / width;

        ECPoint R = c.getInfinity();

        for (int i = d - 1; i >= 0; --i)
        {
            int index = 0;
            for (int j = width - 1; j >= 0; --j)
            {
                index <<= 1;
                if (k.testBit(j * d + i))
                {
                    index |= 1;
                }
            }

            R = R.twicePlus(lookupTable[index]);
        }

        return R;
    }
}
