package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class DoubleAddMultiplier implements ECMultiplier
{
    /**
     * Joye's double-add algorithm.
     */
    public ECPoint multiply(ECPoint p, BigInteger k, PreCompInfo preCompInfo)
    {
        ECPoint[] R = new ECPoint[]{ p.getCurve().getInfinity(), p };

        int n = k.bitLength();
        for (int i = 0; i < n; ++i)
        {
            int b = k.testBit(i) ? 1 : 0;
            int bp = 1 - b;
            R[bp] = R[bp].twicePlus(R[b]);
        }
        return R[0];
    }
}
