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
        WNafPreCompInfo wnafPreCompInfo;

        if ((preCompInfo != null) && (preCompInfo instanceof WNafPreCompInfo))
        {
            wnafPreCompInfo = (WNafPreCompInfo)preCompInfo;
        }
        else
        {
            // Ignore empty PreCompInfo or PreCompInfo of incorrect type
            wnafPreCompInfo = new WNafPreCompInfo();
        }

        // floor(log2(k))
        int m = k.bitLength();

        // Clamp the window size in the range [2, 8]
        int w = Math.max(2, Math.min(8, getWindowSize(m)));

        // width of the Window NAF
        byte width = (byte)w;
        // Required length of precomputation array
        int reqPreCompLen = 1 << (w - 2);

        // The length of the precomputation array
        int preCompLen = 1;

        ECPoint[] preComp = wnafPreCompInfo.getPreComp();
        ECPoint twiceP = wnafPreCompInfo.getTwiceP();

        // Check if the precomputed ECPoints already exist
        if (preComp == null)
        {
            // Precomputation must be performed from scratch, create an empty array of desired length
            preComp = new ECPoint[]{ p.normalize() };
        }
        else
        {
            // Take the already precomputed ECPoints to start with
            preCompLen = preComp.length;
        }

        if (twiceP == null)
        {
            // Compute twice(p)
            twiceP = p.twice().normalize();
        }

        if (preCompLen < reqPreCompLen)
        {
            // Precomputation array must be made bigger, copy existing preComp
            // array into the larger new preComp array
            ECPoint[] oldPreComp = preComp;
            preComp = new ECPoint[reqPreCompLen];
            System.arraycopy(oldPreComp, 0, preComp, 0, preCompLen);

            for (int i = preCompLen; i < reqPreCompLen; i++)
            {
                // Compute the new ECPoints for the precomputation array.
                // The values 1, 3, 5, ..., 2^(width-1)-1 times p are
                // computed
                preComp[i] = twiceP.add(preComp[i - 1]).normalize();
            }            
        }

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

        // Set PreCompInfo in ECPoint, such that it is available for next
        // multiplication.
        wnafPreCompInfo.setPreComp(preComp);
        wnafPreCompInfo.setTwiceP(twiceP);
        p.setPreCompInfo(wnafPreCompInfo);
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
