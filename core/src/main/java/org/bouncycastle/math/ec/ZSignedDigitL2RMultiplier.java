package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class ZSignedDigitL2RMultiplier implements ECMultiplier
{
    /**
     * 'Zeroless' Signed Digit Left-to-Right.
     */
    public ECPoint multiply(ECPoint p, BigInteger k, PreCompInfo preCompInfo)
    {
        p = p.normalize();
        ECPoint R0 = p, negP = p.negate();

        int s = k.getLowestSetBit();
        int i = k.bitLength();
        while (--i > s)
        {
            R0 = R0.twicePlus(k.testBit(i) ? p : negP);
        }
        R0 = R0.timesPow2(s);
        return R0;
    }
}
