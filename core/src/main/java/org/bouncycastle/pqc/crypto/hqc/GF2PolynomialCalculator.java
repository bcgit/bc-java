package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class GF2PolynomialCalculator
{
    private final int bits;
    private final int size;
    private final int sizeExt;

    GF2PolynomialCalculator(int n)
    {
        if ((n & 0xFFFF0001) != 1)
            throw new IllegalArgumentException();

        bits = n;
        size = Utils.getByte64SizeFromBitSize(n);
        sizeExt = size * 2;
    }

    void addTo(long[] x, long[] z)
    {
        Nat.xorTo64(size, x, z);
    }

    long[] create()
    {
        return new long[size];
    }

    long[] createExt()
    {
        return new long[sizeExt];
    }

    long equalTo(long[] x, long[] y)
    {
        return Nat.equalTo64(size, x, y);
    }

    void mul(long[] o, long[] a1, long[] a2)
    {
        long[] zz = createExt();
        long[] tmp = new long[size << 4];
        karatsuba(zz, 0, a1, 0, a2, 0, size, tmp, 0);
        reduce(o, zz);
    }

    void random(Shake256RandomGenerator generator, long[] z)
    {
        byte[] tmp = new byte[size << 3];
        generator.xofGetBytes(tmp, Utils.getByteSizeFromBitSize(bits));
        Pack.littleEndianToLong(tmp, 0, z);
        z[size - 1] &= (1L << (bits & 63)) - 1L;
    }

    /**
     * Performs schoolbook multiplication over GF(2).
     *
     * <p>This method computes {@code r = a * b}, where {@code a} and {@code b} are
     * polynomials over GF(2), each represented as {@code n} 64-bit words. The result
     * is stored in {@code r} as {@code 2 * n} 64-bit words.</p>
     */
    private void baseMul(long[] r, int rOff, long[] a, int aOff, long[] b, int bOff, int n)
    {
        Arrays.fill(r, rOff, rOff + (n << 1), 0L);

        long[] u = new long[16];

        // Schoolbook

//        for (int i = 0; i < n; ++i)
//        {
//            long x_i = a[aOff + i];
//
//            for (int j = 0; j < n; ++j)
//            {
//                long y_j = b[bOff + j];
//
//                implMulwAcc(u, x_i, y_j, r, rOff + i + j);
//            }
//        }

        // Arbitrary-degree Karatsuba

        for (int i = 0; i < n; ++i)
        {
            implMulwAcc(u, a[aOff + i], b[bOff + i], r, rOff + (i << 1));
        }

        long v0 = r[rOff], v1 = r[rOff + 1];
        for (int i = 1; i < n; ++i)
        {
            v0 ^= r[rOff + (i << 1)]; r[rOff + i] = v0 ^ v1; v1 ^= r[rOff + (i << 1) + 1];
        }

        long w = v0 ^ v1;
        Nat.xor64(n, r, rOff, w, r, rOff + n);

        int last = n - 1;
        for (int zPos = 1; zPos < (last * 2); ++zPos)
        {
            int hi = Math.min(last, zPos);
            int lo = zPos - hi;

            while (lo < hi)
            {
                implMulwAcc(u, a[aOff + lo] ^ a[aOff + hi], b[bOff + lo] ^ b[bOff + hi], r, rOff + zPos);

                ++lo;
                --hi;
            }
        }
    }

    /**
     * Performs Karatsuba multiplication over GF(2) using a caller-supplied temporary buffer.
     *
     * <p>If {@code n <= 16}, this method falls back to
     * {@link #baseMul(long[], int, long[], int, long[], int, int)}.
     * Otherwise, the operands are split in half and the algorithm is applied recursively.</p>
     *
     */
    private void karatsuba(long[] r, int rOffset, long[] a, int aOffset, long[] b, int bOffset, int n, long[] tmpBuffer,
        int tmpOffset)
    {
        if (n < 8)
        {
            baseMul(r, rOffset, a, aOffset, b, bOffset, n);
            return;
        }

        // NB: This only works for n > 4
//        assert n > 4;

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
        int partialBits = bits & 63;
        int excessBits = 64 - partialBits;
        long partialMask = -1L >>> excessBits;

//        long c =
        Nat.shiftUpBits64(size, a, size, excessBits, a[size - 1], o, 0);
//        assert c == 0L;
        addTo(a, o);
        o[size - 1] &= partialMask;
    }

    /**
     * Carryless multiply of x and y, accumulating the result at z[zOff..zOff + 1], using u as a temporary buffer.
     */
    private static void implMulwAcc(long[] u, long x, long y, long[] z, int zOff)
    {
//      u[0] = 0;
        u[1] = y;
        for (int i = 2; i < 16; i += 2)
        {
            u[i    ] = u[i >>> 1] << 1;
            u[i + 1] = u[i      ] ^  y;
        }

        int j = (int)x;
        long g, h = 0, l = u[j & 15]
                         ^ u[(j >>> 4) & 15] << 4;
        int k = 56;
        do
        {
            j  = (int)(x >>> k);
            g  = u[j & 15]
               ^ u[(j >>> 4) & 15] << 4;
            l ^= (g << k);
            h ^= (g >>> -k);
        }
        while ((k -= 8) > 0);

        for (int p = 0; p < 7; ++p)
        {
            x = (x & 0xFEFEFEFEFEFEFEFEL) >>> 1;
            h ^= x & ((y << p) >> 63);
        }

//        assert h >>> 63 == 0;

        z[zOff    ] ^= l;
        z[zOff + 1] ^= h;
    }
}
