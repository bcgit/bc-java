package org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class WNafUtil
{
    private static int[] DEFAULT_WINDOW_SIZE_CUTOFFS = new int[]{ 13, 41, 121, 337, 897, 2305 };

    public static int[] generateCompactNaf(BigInteger k)
    {
        BigInteger _3k = k.shiftLeft(1).add(k);

        int digits = _3k.bitLength() - 1;
        int[] naf = new int[(digits + 1) >> 1];

        int length = 0, zeroes = 0;
        for (int i = 1; i <= digits; ++i)
        {
            boolean _3kBit = _3k.testBit(i);
            boolean kBit = k.testBit(i);

            if (_3kBit == kBit)
            {
                ++zeroes;
            }
            else
            {
                int digit  = kBit ? -1 : 1;
                naf[length++] = (digit << 16) | zeroes;
                zeroes = 0;
            }
        }

        if (naf.length > length)
        {
            naf = trim(naf, length);
        }

        return naf;
    }

    public static int[] generateCompactWindowNaf(int width, BigInteger k)
    {
        if (width == 2)
        {
            return generateCompactNaf(k);
        }

        if (width < 2 || width > 8)
        {
            throw new IllegalArgumentException("'width' must be in the range [2, 8]");
        }

        int[] wnaf = new int[k.bitLength() / width + 1];

        // 2^width and a mask and sign bit set accordingly
        int pow2 = 1 << width;
        int mask = pow2 - 1;
        int sign = pow2 >>> 1;

        boolean carry = false;
        int length = 0, pos = 0;

        while (pos <= k.bitLength())
        {
            if (k.testBit(pos) == carry)
            {
                ++pos;
                continue;
            }

            k = k.shiftRight(pos);

            int digit = k.intValue() & mask;
            if (carry)
            {
                ++digit;
            }

            carry = (digit & sign) != 0;
            if (carry)
            {
                digit -= pow2;
            }

            int zeroes = length > 0 ? pos - 1 : pos;
            wnaf[length++] = (digit << 16) | zeroes;
            pos = width;
        }

        // Reduce the WNAF array to its actual length
        if (wnaf.length > length)
        {
            wnaf = trim(wnaf, length);
        }

        return wnaf;
    }

    public static byte[] generateNaf(BigInteger k)
    {
        BigInteger _3k = k.shiftLeft(1).add(k);

        int digits = _3k.bitLength() - 1;
        byte[] naf = new byte[digits];

        for (int i = 1; i <= digits; ++i)
        {
            boolean _3kBit = _3k.testBit(i);
            boolean kBit = k.testBit(i);

            naf[i - 1] = (byte)(_3kBit == kBit ? 0 : kBit ? -1 : 1);
        }

        return naf;
    }

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
    public static byte[] generateWindowNaf(int width, BigInteger k)
    {
        if (width == 2)
        {
            return generateNaf(k);
        }

        if (width < 2 || width > 8)
        {
            throw new IllegalArgumentException("'width' must be in the range [2, 8]");
        }

        // The window NAF is at most 1 element longer than the binary
        // representation of the integer k. byte can be used instead of short or
        // int unless the window width is larger than 8. For larger width use
        // short or int. However, a width of more than 8 is not efficient for
        // m = log2(q) smaller than 2305 Bits. Note: Values for m larger than
        // 1000 Bits are currently not used in practice.
        byte[] wnaf = new byte[k.bitLength() + 1];

        // 2^width and a mask and sign bit set accordingly
        int pow2 = 1 << width;
        int mask = pow2 - 1;
        int sign = pow2 >>> 1;

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
                int digit = k.intValue() & mask;
                if ((digit & sign) != 0)
                {
                    digit -= pow2;
                }

                // wnaf[i] is now in [-2^(width-1), 2^(width-1)-1]
                wnaf[i] = (byte)digit;

                k = k.subtract(BigInteger.valueOf(digit));
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
        if (wnaf.length > length)
        {
            wnaf = trim(wnaf, length);
        }
        
        return wnaf;
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

    private static byte[] trim(byte[] bs, int length)
    {
        byte[] result = new byte[length];
        System.arraycopy(bs, 0, result, 0, result.length);
        return result;
    }

    private static int[] trim(int[] bs, int length)
    {
        int[] result = new int[length];
        System.arraycopy(bs, 0, result, 0, result.length);
        return result;
    }

    private static ECPoint[] resizeTable(ECPoint[] ps, int length)
    {
        ECPoint[] result = new ECPoint[length];
        System.arraycopy(ps, 0, result, 0, ps.length);
        return result;
    }
}
