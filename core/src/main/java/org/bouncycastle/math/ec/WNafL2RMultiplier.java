package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the WNAF (Window Non-Adjacent Form) multiplication
 * algorithm.
 */
public class WNafL2RMultiplier implements ECMultiplier
{
    /**
     * Multiplies <code>this</code> by an integer <code>k</code> using the
     * Window NAF method.
     * @param k The integer by which <code>this</code> is multiplied.
     * @return A new <code>ECPoint</code> which equals <code>this</code>
     * multiplied by <code>k</code>.
     */
    public ECPoint multiply(ECPoint p, BigInteger k, PreCompInfo preCompInfo)
    {
        // floor(log2(k))
        int m = k.bitLength();

        // Clamp the window size in the range [2, 8]
        int w = Math.max(2, Math.min(8, getWindowSize(m)));

        // width of the Window NAF
        byte width = (byte)w;

        WNafPreCompInfo wnafPreCompInfo = WNafUtil.precompute(p, preCompInfo, w);
        ECPoint[] preComp = wnafPreCompInfo.getPreComp();

        // Compute the Window NAF of the desired width
        byte[] wnaf = WNafUtil.generateWindowNaf(width, k);
        int l = wnaf.length;

        // Apply the Window NAF to p using the precomputed ECPoint values.
        ECPoint q = p.getCurve().getInfinity();
        for (int i = l - 1; i >= 0; i--)
        {
            int wi = wnaf[i];
            if (wi == 0)
            {
                q = q.twice();
            }
            else
            {
                int index = (Math.abs(wi) - 1) / 2;
                ECPoint r = preComp[index];
                if (wi < 0)
                {
                    r = r.negate();
                }

                q = q.twicePlus(r);
            }
        }

        return q;
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
