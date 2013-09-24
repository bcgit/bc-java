package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the NAF (Non-Adjacent Form) multiplication algorithm.
 */
public class FpNafMultiplier implements ECMultiplier
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

        byte[] wnaf = WNafUtil.generateNaf(k);

        p = p.normalize();

        ECPoint negP = p.negate();
        ECPoint R = p.getCurve().getInfinity();

        int i = wnaf.length;
        while (--i >= 0)
        {
            int wi = wnaf[i];
            if (wi == 0)
            {
                R = R.twice();
            }
            else
            {
                ECPoint r = wi > 0 ? p : negP;
                R = R.twicePlus(r);
            }
        }

        return R;
    }
}
