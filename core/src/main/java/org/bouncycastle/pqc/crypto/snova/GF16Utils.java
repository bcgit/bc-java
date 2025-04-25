package org.bouncycastle.pqc.crypto.snova;

import org.bouncycastle.util.GF16;

class GF16Utils
{
    static void encodeMergeInHalf(byte[] m, int mlen, byte[] menc)
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

    static void decodeMergeInHalf(byte[] byteArray, byte[] gf16Array, int nGf16)
    {
        int i, half = (nGf16 + 1) >>> 1;
        // Process pairs of 4-bit values
        for (i = 0; i < half; i++)
        {
            gf16Array[i] = (byte)(byteArray[i] & 0x0F);
            gf16Array[i + half] = (byte)((byteArray[i] >>> 4) & 0x0F);
        }
    }

    static void gf16mTranMulMul(byte[] sign, int signOff, byte[] a, byte[] b, byte[] q1, byte[] q2, byte[] tmp,
                                byte[] left, byte[] right, int rank)
    {
        for (int i = 0, leftOff = 0, dOff = 0; i < rank; i++, leftOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                byte result = 0;
                for (int k = 0, aOff = signOff + j, bOff = i; k < rank; ++k, aOff += rank, bOff += rank)
                {
                    result ^= GF16.mul(sign[aOff], q1[bOff]);
                }
                tmp[j] = result;
            }

            for (int j = 0, jxl = 0; j < rank; j++, jxl += rank)
            {
                byte result = 0;
                for (int k = 0; k < rank; ++k)
                {
                    result ^= GF16.mul(a[jxl + k], tmp[k]);
                }
                left[i + jxl] = result;
            }
            for (int j = 0; j < rank; j++)
            {
                tmp[j] = GF16.innerProduct(q2, leftOff, sign, signOff + j, rank);
            }

            for (int j = 0; j < rank; j++)
            {
                right[dOff++] = GF16.innerProduct(tmp, 0, b, j, rank);
            }
        }
    }

    // tmp = a * b, d = tmp * c -> d = (a * b) * c
    static void gf16mMulMul(byte[] a, byte[] b, byte[] c, byte[] tmp, byte[] d, int rank)
    {
        for (int i = 0, leftOff = 0, dOff = 0; i < rank; i++, leftOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                tmp[j] = GF16.innerProduct(a, leftOff, b, j, rank);
            }

            for (int j = 0; j < rank; j++)
            {
                d[dOff++] = GF16.innerProduct(tmp, 0, c, j, rank);
            }
        }
    }

    static void gf16mMul(byte[] a, byte[] b, byte[] c, int rank)
    {
        for (int i = 0, aOff = 0, cOff = 0; i < rank; i++, aOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                c[cOff++] = GF16.innerProduct(a, aOff, b, j, rank);
            }
        }
    }

    static void gf16mMulMulTo(byte[] a, byte[] b, byte[] c, byte[] tmp, byte[] d, int rank)
    {
        for (int i = 0, leftOff = 0, dOff = 0; i < rank; i++, leftOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                tmp[j] = GF16.innerProduct(a, leftOff, b, j, rank);
            }

            for (int j = 0; j < rank; j++)
            {
                d[dOff++] ^= GF16.innerProduct(tmp, 0, c, j, rank);
            }
        }
    }

    static void gf16mMulTo(byte[] a, byte[] b, byte[] c, int rank)
    {
        for (int i = 0, aOff = 0, cOff = 0; i < rank; i++, aOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                c[cOff++] ^= GF16.innerProduct(a, aOff, b, j, rank);
            }
        }
    }

    // d = a * b, e = b * c
    static void gf16mMulToTo(byte[] a, byte[] b, byte[] c, byte[] d, byte[] e, int rank)
    {
        for (int i = 0, leftOff = 0, outOff = 0; i < rank; i++, leftOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                d[outOff] ^= GF16.innerProduct(a, leftOff, b, j, rank);
                e[outOff++] ^= GF16.innerProduct(b, leftOff, c, j, rank);
            }
        }
    }

    static void gf16mMulTo(byte[] a, byte[] b, byte[] c, int cOff, int rank)
    {
        for (int i = 0, aOff = 0; i < rank; i++, aOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                c[cOff++] ^= GF16.innerProduct(a, aOff, b, j, rank);
            }
        }
    }

    // d ^= a * b + c * d
    static void gf16mMulTo(byte[] a, byte[] b, byte[] c, byte[] d, byte[] e, int eOff, int rank)
    {
        for (int i = 0, leftOff = 0; i < rank; i++, leftOff += rank)
        {
            for (int j = 0; j < rank; j++)
            {
                e[eOff++] ^= GF16.innerProduct(a, leftOff, b, j, rank) ^ GF16.innerProduct(c, leftOff, d, j, rank);
            }
        }
    }

    static void gf16mMulTo(byte[] a, byte[] b, int bOff, byte[] c, int cOff, int rank)
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
    static int gf16FromNibble(int idx)
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