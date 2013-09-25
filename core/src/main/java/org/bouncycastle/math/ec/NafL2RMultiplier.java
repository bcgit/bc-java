package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the NAF (Non-Adjacent Form) multiplication algorithm (left-to-right).
 */
public class NafL2RMultiplier implements ECMultiplier
{
    /**
     * D.3.2 pg 101
     * @see org.bouncycastle.math.ec.ECMultiplier#multiply(org.bouncycastle.math.ec.ECPoint, java.math.BigInteger)
     */
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

        int[] naf = WNafUtil.generateCompactNaf(k);

        p = p.normalize();

        ECPoint negP = p.negate();
        ECPoint R = p.getCurve().getInfinity();

        int i = naf.length;
        while (--i >= 0)
        {
            int ni = naf[i];
            int digit = ni >> 16, zeroes = ni & 0xFFFF;

            R = R.twicePlus(digit > 0 ? p : negP);
            R = R.timesPow2(zeroes);
        }

        return R;
    }
}
