package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.util.GF16;

class GF16Utils
{
    public static void encodeMergeInHalf(byte[] m, int mlen, byte[] menc)
    {
        int i, half = (mlen + 1) >>> 1;
        // Process pairs of 4-bit values
        for (i = 0; i < mlen / 2; i++, half++)
        {
            menc[i] = (byte)(m[i] | (m[half] << 4));
        }
        // If there is an extra nibble (odd number of nibbles), store it directly in lower 4 bits.
        if ((mlen & 1) == 1)
        {
            menc[i] = m[i];
        }
    }

    public static void decodeMergeInHalf(byte[] byteArray, byte[] gf16Array, int nGf16)
    {
        int i, half = (nGf16 + 1) >>> 1;
        // Process pairs of 4-bit values
        for (i = 0; i < half; i++)
        {
            gf16Array[i] = (byte)(byteArray[i] & 0x0F);
            gf16Array[i + half] = (byte)((byteArray[i] >>> 4) & 0x0F);
        }
    }

    public static void gf16mTranMul(byte[] a, byte[] b, byte[] c, int rank)
    {
        for (int i = 0, cOff = 0; i < rank; i++)
        {
            for (int j = 0, jl = 0; j < rank; j++, jl += rank)
            {
                c[cOff++] = GF16.dotProduct(a, i, b, j, rank);
            }
        }
    }

    public static void gf16mMul(byte[] a, byte[] b, byte[] c, int rank)
    {
        for (int i = 0, aOff = 0, cOff = 0; i < rank; i++, aOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                c[cOff++] = GF16.innerProduct(a, aOff, b, j, rank);
            }
        }
    }

    public static void gf16mMulTo(byte[] a, byte[] b, byte[] c, int rank)
    {
        for (int i = 0, aOff = 0, cOff = 0; i < rank; i++, aOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                c[cOff++] ^= GF16.innerProduct(a, aOff, b, j, rank);
            }
        }
    }

    public static void gf16mMulTo(byte[] a, byte[] b, int bOff, byte[] c, int cOff, int rank)
    {
        for (int i = 0, aOff = 0; i < rank; i++, aOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                c[cOff++] ^= GF16.innerProduct(a, aOff, b, bOff + j, rank);
            }
        }
    }

    /**
     * Conversion 4 bit -> 32 bit representation
     */
    public static int gf16FromNibble(int idx)
    {
        int middle = idx | (idx << 4);
        return ((middle & 0x41) | ((middle << 2) & 0x208));
    }

    private static final int GF16_MASK = 0x249; // Mask for GF(2^4) reduction

    // Constant-time GF16 != 0 check
    static int ctGF16IsNotZero(byte val)
    {
        int v = val & 0xFF;
        return (v | (v >>> 1) | (v >>> 2) | (v >>> 3)) & 1;
    }

    // GF16 reduction modulo x^4 + x + 1
    private static int gf16Reduce(int idx)
    {
        int res = idx & 0x49249249;
        int upper = idx >>> 12;
        res ^= upper ^ (upper << 3);
        upper = res >>> 12;
        res ^= upper ^ (upper << 3);
        upper = res >>> 12;
        res ^= upper ^ (upper << 3);
        return res & GF16_MASK;
    }

    // Convert 32-bit reduced value to 4-bit nibble
    static byte gf16ToNibble(int val)
    {
        int res = gf16Reduce(val);
        res |= res >>> 4;
        return (byte)((res & 0x5) | ((res >>> 2) & 0xA));
    }
}