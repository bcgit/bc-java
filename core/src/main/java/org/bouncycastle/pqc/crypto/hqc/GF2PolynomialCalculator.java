package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.util.Arrays;

class GF2PolynomialCalculator
{
    private final int VEC_N_SIZE_64;
    private final int PARAM_N;
    private final long RED_MASK;

    GF2PolynomialCalculator(int vec_n_size_64, int param_n, long red_mask)
    {
        VEC_N_SIZE_64 = vec_n_size_64;
        PARAM_N = param_n;
        RED_MASK = red_mask;
    }

    public void vectMul(long[] o, long[] a1, long[] a2)
    {
        long[] unreduced = new long[VEC_N_SIZE_64 << 1];
        long[] tmpBuffer = new long[VEC_N_SIZE_64 << 4];
        karatsuba(unreduced, 0, a1, 0, a2, 0, VEC_N_SIZE_64, tmpBuffer, 0);
        reduce(o, unreduced);
    }

    /**
     * Performs schoolbook multiplication over GF(2).
     *
     * <p>This method computes {@code r = a * b}, where {@code a} and {@code b} are
     * polynomials over GF(2), each represented as {@code n} 64-bit words. The result
     * is stored in {@code r} as {@code 2 * n} 64-bit words.</p>
     */
    private void schoolbookMul(long[] r, int rOff, long[] a, int aOff, long[] b, int bOff, int n)
    {
        Arrays.fill(r, rOff, rOff + (n << 1), 0L);

        for (int i = 0; i < n; i++, rOff++)
        {
            long ai = a[i + aOff];
            for (int bit = 0; bit < 64; bit++)
            {
                long mask = -((ai >> bit) & 1L);
                if (bit == 0)
                {
                    for (int j = 0, rOff1 = rOff, bOff1 = bOff; j < n; j++, rOff1++, bOff1++)
                    {
                        r[rOff1] ^= b[bOff1] & mask;
                    }
                }
                else
                {
                    int inv = 64 - bit;
                    for (int j = 0, rOff1 = rOff, bOff1 = bOff; j < n; j++, bOff1++)
                    {
                        r[rOff1++] ^= (b[bOff1] << bit) & mask;
                        r[rOff1] ^= (b[bOff1] >>> inv) & mask;
                    }
                }
            }
        }
    }

    /**
     * Performs Karatsuba multiplication over GF(2) using a caller-supplied temporary buffer.
     *
     * <p>If {@code n <= 16}, this method falls back to
     * {@link #schoolbookMul(long[], int, long[], int, long[], int, int)}.
     * Otherwise, the operands are split in half and the algorithm is applied recursively.</p>
     *
     */
    private void karatsuba(long[] r, int rOffset, long[] a, int aOffset,
                           long[] b, int bOffset, int n, long[] tmpBuffer, int tmpOffset)
    {
        if (n <= 16)
        {
            schoolbookMul(r, rOffset, a, aOffset, b, bOffset, n);
            return;
        }

        int m = n >> 1;
        int n1 = n - m;
        int nx2 = n << 1;
        int mx2 = m << 1;
        int n1x2 = n1 << 1;

        int z2Offset = tmpOffset + nx2;
        int zMidOffset = z2Offset + nx2;
        int taOffset = zMidOffset + nx2;
        int tbOffset = taOffset + n;
        int childBufferOffset = tmpOffset + (n << 3);

        karatsuba(tmpBuffer, tmpOffset, a, aOffset, b, bOffset, m, tmpBuffer, childBufferOffset);
        karatsuba(tmpBuffer, z2Offset, a, aOffset + m, b, bOffset + m, n1, tmpBuffer, childBufferOffset);

        for (int i = 0; i < n1; i++)
        {
            long loa = (i < m) ? a[aOffset + i] : 0;
            long lob = (i < m) ? b[bOffset + i] : 0;
            tmpBuffer[taOffset + i] = loa ^ a[aOffset + m + i];
            tmpBuffer[tbOffset + i] = lob ^ b[bOffset + m + i];
        }

        karatsuba(tmpBuffer, zMidOffset, tmpBuffer, taOffset, tmpBuffer, tbOffset, n1, tmpBuffer, childBufferOffset);

        System.arraycopy(tmpBuffer, tmpOffset, r, rOffset, mx2);
        System.arraycopy(tmpBuffer, z2Offset, r, rOffset + mx2, n1x2);

        for (int i = 0; i < 2 * n1; i++)
        {
            long z0i = (i < mx2) ? tmpBuffer[tmpOffset + i] : 0;
            long z2i = (i < n1x2) ? tmpBuffer[z2Offset + i] : 0;
            r[rOffset + m + i] ^= tmpBuffer[zMidOffset + i] ^ z0i ^ z2i;
        }
    }

    /**
     * Reduces a polynomial modulo {@code X^n - 1}.
     *
     * <p>This computes {@code o(x) = a(x) mod (X^n - 1)}, where
     * {@code a(x)} may have degree up to {@code 2n - 2}. The result
     * is a polynomial of degree less than {@code n}, represented as
     * {@code n} 64-bit words.</p>
     *
     * @param o  the result buffer of length {@code n} words,
     *           where the reduced polynomial is stored
     * @param a  the input polynomial to be reduced
     */
    private void reduce(long[] o, long[] a)
    {
        for (int i = 0; i < VEC_N_SIZE_64; i++)
        {
            o[i] = a[i] ^ (a[i + VEC_N_SIZE_64 - 1] >>> (PARAM_N & 0x3F)) ^ ((a[i + VEC_N_SIZE_64] << (64 - (PARAM_N & 0x3FL))));
        }
        o[VEC_N_SIZE_64 - 1] &= RED_MASK;
    }
}