package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class ZSignedDigitR2LMultiplier implements ECMultiplier
{
    /**
     * 'Zeroless' Signed Digit Right-to-Left.
     */
    public ECPoint multiply(ECPoint p, BigInteger k, PreCompInfo preCompInfo)
    {
        ECPoint R0 = p.getCurve().getInfinity(), R1 = p;

        int n = k.bitLength();
        int s = k.getLowestSetBit();

        int i = 0;
        for (; i < s; ++i)
        {
            R1 = R1.twice();
        }
        while (++i < n)
        {
            ECPoint r = k.testBit(i) ? R1 : R1.negate();
            R0 = R0.add(r);
            R1 = R1.twice();
        }
        R0 = R0.add(R1);
        return R0;
    }
}
