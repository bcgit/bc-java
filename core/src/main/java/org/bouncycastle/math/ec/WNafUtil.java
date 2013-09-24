package org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class WNafUtil
{
    private static int[] DEFAULT_WINDOW_SIZE_CUTOFFS = new int[]{ 13, 41, 121, 337, 897, 2305 };

    /**
     * Computes the Window NAF (non-adjacent Form) of an integer.
     * @param width The width <code>w</code> of the Window NAF. The width is
     * defined as the minimal number <code>w</code>, such that for any
     * <code>w</code> consecutive digits in the resulting representation, at
     * most one is non-zero.
     * @param k The integer of which the Window NAF is computed.
     * @return The Window NAF of the given width, such that the following holds:
     * <code>k = &sum;<sub>i=0</sub><sup>l-1</sup> k<sub>i</sub>2<sup>i</sup>
     * </code>, where the <code>k<sub>i</sub></code> denote the elements of the
     * returned <code>byte[]</code>.
     */
    public static byte[] generateWindowNaf(byte width, BigInteger k)
    {
        // The window NAF is at most 1 element longer than the binary
        // representation of the integer k. byte can be used instead of short or
        // int unless the window width is larger than 8. For larger width use
        // short or int. However, a width of more than 8 is not efficient for
        // m = log2(q) smaller than 2305 Bits. Note: Values for m larger than
        // 1000 Bits are currently not used in practice.
        byte[] wnaf = new byte[k.bitLength() + 1];

        // 2^width as short and BigInteger
        short pow2wB = (short)(1 << width);
        BigInteger pow2wBI = BigInteger.valueOf(pow2wB);

        int i = 0;

        // The actual length of the WNAF
        int length = 0;

        // while k >= 1
        while (k.signum() > 0)
        {
            // if k is odd
            if (k.testBit(0))
            {
                // k mod 2^width
                BigInteger remainder = k.mod(pow2wBI);

                // if remainder > 2^(width - 1) - 1
                if (remainder.testBit(width - 1))
                {
                    wnaf[i] = (byte)(remainder.intValue() - pow2wB);
                }
                else
                {
                    wnaf[i] = (byte)remainder.intValue();
                }
                // wnaf[i] is now in [-2^(width-1), 2^(width-1)-1]

                k = k.subtract(BigInteger.valueOf(wnaf[i]));
                length = i;
            }
            else
            {
                wnaf[i] = 0;
            }

            // k = k/2
            k = k.shiftRight(1);
            i++;
        }

        length++;

        // Reduce the WNAF array to its actual length
        byte[] wnafShort = new byte[length];
        System.arraycopy(wnaf, 0, wnafShort, 0, length);
        return wnafShort;
    }

    public static WNafPreCompInfo getWNafPreCompInfo(PreCompInfo preCompInfo)
    {
        if ((preCompInfo != null) && (preCompInfo instanceof WNafPreCompInfo))
        {
            return (WNafPreCompInfo)preCompInfo;
        }

        return new WNafPreCompInfo();
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     * 
     * @param bits the bit-length of the scalar to multiply by
     * @return the window size to use
     */
    public static int getWindowSize(int bits)
    {
        return getWindowSize(bits, DEFAULT_WINDOW_SIZE_CUTOFFS);
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     * 
     * @param bits the bit-length of the scalar to multiply by
     * @param windowSizeCutoffs a monotonically increasing list of bit sizes at which to increment the window width
     * @return the window size to use
     */
    public static int getWindowSize(int bits, int[] windowSizeCutoffs)
    {
        int w = 0;
        for (; w < windowSizeCutoffs.length; ++w)
        {
            if (bits < windowSizeCutoffs[w])
            {
                break;
            }
        }
        return w + 2;
    }

    public static WNafPreCompInfo precompute(ECPoint p, PreCompInfo preCompInfo, int width)
    {
        WNafPreCompInfo wnafPreCompInfo = getWNafPreCompInfo(preCompInfo);

        ECPoint[] preComp = wnafPreCompInfo.getPreComp();
        if (preComp == null)
        {
            preComp = new ECPoint[]{ p.normalize() };
        }

        int preCompLen = preComp.length;
        int reqPreCompLen = 1 << Math.max(0, width - 2);

        if (preCompLen < reqPreCompLen)
        {
            ECPoint twiceP = wnafPreCompInfo.getTwiceP();
            if (twiceP == null)
            {
                twiceP = p.twice().normalize();
                wnafPreCompInfo.setTwiceP(twiceP);
            }

            preComp = resizeTable(preComp, reqPreCompLen);
            for (int i = preCompLen; i < reqPreCompLen; i++)
            {
                /*
                 * Compute the new ECPoints for the precomputation array. The values 1, 3, 5, ...,
                 * 2^(width-1)-1 times p are computed
                 */
                preComp[i] = twiceP.add(preComp[i - 1]).normalize();
            }            
        }

        wnafPreCompInfo.setPreComp(preComp);
        p.setPreCompInfo(wnafPreCompInfo);

        return wnafPreCompInfo;
    }

    private static ECPoint[] resizeTable(ECPoint[] ps, int length)
    {
        ECPoint[] result = new ECPoint[length];
        System.arraycopy(ps, 0, result, 0, ps.length);
        return result;
    }
}
