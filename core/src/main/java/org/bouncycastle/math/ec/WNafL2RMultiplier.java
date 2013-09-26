package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the WNAF (Window Non-Adjacent Form) multiplication
 * algorithm.
 */
public class WNafL2RMultiplier extends AbstractECMultiplier
{
    /**
     * Multiplies <code>this</code> by an integer <code>k</code> using the
     * Window NAF method.
     * @param k The integer by which <code>this</code> is multiplied.
     * @return A new <code>ECPoint</code> which equals <code>this</code>
     * multiplied by <code>k</code>.
     */
    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        ECPoint R = p.getCurve().getInfinity();

        // Clamp the window width in the range [2, 16]
        int width = Math.max(2, Math.min(16, getWindowSize(k.bitLength())));

        WNafPreCompInfo wnafPreCompInfo = WNafUtil.precompute(p, width, true);
        ECPoint[] preComp = wnafPreCompInfo.getPreComp();
        ECPoint[] preCompNeg = wnafPreCompInfo.getPreCompNeg();

        int[] wnaf = WNafUtil.generateCompactWindowNaf(width, k);

        int i = wnaf.length;
        while (--i >= 0)
        {
            int wi = wnaf[i];
            int digit = wi >> 16, zeroes = wi & 0xFFFF;

            int index = (Math.abs(digit) - 1) >>> 1;
            ECPoint r = wi < 0 ? preCompNeg[index] : preComp[index];

            R = R.twicePlus(r);
            R = R.timesPow2(zeroes);
        }

        return R;
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     * 
     * @param bits the bit-length of the scalar to multiply by
     * @return the window size to use
     */
    protected int getWindowSize(int bits)
    {
        return WNafUtil.getWindowSize(bits);
    }
}
