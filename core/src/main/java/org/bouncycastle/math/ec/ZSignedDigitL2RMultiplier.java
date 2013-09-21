package org.bouncycastle.math.ec;

import java.math.BigInteger;

class ZSignedDigitL2RMultiplier implements ECMultiplier
{
    /**
     * 'Zeroless' Signed Digit Left-to-Right.
     */
    public ECPoint multiply(ECPoint p, BigInteger k, PreCompInfo preCompInfo)
    {
        ECPoint R0 = p, negP = p.negate();

        int n = k.bitLength();
        int s = k.getLowestSetBit();

        int i = n;
        while (--i > s)
        {
            ECPoint r = k.testBit(i) ? p : negP;
            R0 = R0.twicePlus(r);
        }
        while (--i >= 0)
        {
            R0 = R0.twice();
        }
        return R0;
    }
}
