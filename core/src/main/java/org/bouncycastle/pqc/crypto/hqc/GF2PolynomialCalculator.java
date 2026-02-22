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

    void clear(long[] z)
    {
        Nat.zero64(size, z);
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

    void mul(long[] x, long[] y, long[] z)
    {
        long[] tt = createExt();
        long[] tmp = new long[size << 4];
        karatsuba(size, x, 0, y, 0, tt, 0, tmp, 0);
        reduce(tt, z);
    }

    void random(Shake256RandomGenerator generator, long[] z)
    {
        byte[] tmp = new byte[size << 3];
        generator.xofGetBytes(tmp, Utils.getByteSizeFromBitSize(bits));
        Pack.littleEndianToLong(tmp, 0, z);
        z[size - 1] &= (1L << (bits & 63)) - 1L;
    }

    /**
     * The base multiplication used by {@link #karatsuba(int, long[], int, long[], int, long[], int, long[], int)} once
     * the lengths become small.
     *
     * <p>This method computes {@code zz = x * y}, where {@code x} and {@code y} are
     * polynomials over GF(2), each represented as {@code len} 64-bit words. The result
     * is stored in {@code zz} as {@code 2 * len} 64-bit words.</p>
     */
    private static void baseMul(int len, long[] x, int xOff, long[] y, int yOff, long[] zz, int zzOff)
    {
        int lenExt = len * 2;
        Arrays.fill(zz, zzOff, zzOff + lenExt, 0L);

        // Arbitrary-degree Karatsuba

        long[] u = new long[16];

        for (int i = 0; i < len; ++i)
        {
            implMulwAcc(u, x[xOff + i], y[yOff + i], zz, zzOff + (i << 1));
        }

        long v0 = zz[zzOff], v1 = zz[zzOff + 1];
        for (int i = 1; i < len; ++i)
        {
            v0 ^= zz[zzOff + (i << 1)]; zz[zzOff + i] = v0 ^ v1; v1 ^= zz[zzOff + (i << 1) + 1];
        }

        Nat.xor64(len, zz, zzOff, v0 ^ v1, zz, zzOff + len);

        int last = len - 1;
        for (int zPos = 1; zPos < (last * 2); ++zPos)
        {
            int hi = Math.min(last, zPos);
            int lo = zPos - hi;

            while (lo < hi)
            {
                implMulwAcc(u, x[xOff + lo] ^ x[xOff + hi], y[yOff + lo] ^ y[yOff + hi], zz, zzOff + zPos);

                ++lo;
                --hi;
            }
        }
    }

    /**
     * Performs Karatsuba multiplication over GF(2) using a caller-supplied temporary buffer.
     *
     * <p>
     * If {@code len < 12}, this method falls back to
     * {@link #baseMul(int, long[], int, long[], int, long[], int)}. Otherwise, the operands are split
     * (approximately) in half and the algorithm is applied recursively.
     * </p>
     */
    private void karatsuba(int len, long[] x, int xOff, long[] y, int yOff, long[] zz, int zzOff, long[] tmp,
        int tmpOff)
    {
        int cutoff = 12;

        if (len < cutoff)
        {
            baseMul(len, x, xOff, y, yOff, zz, zzOff);
            return;
        }

        // NB: This only works for n > 4
//        assert len > 4;

        int m = len >> 1;
        int n1 = len - m;
        int nx2 = len << 1;
        int mx2 = m << 1;
        int n1x2 = n1 << 1;

        int z2Offset = tmpOff + nx2;
        int zMidOffset = z2Offset + nx2;
        int taOffset = zMidOffset + nx2;
        int tbOffset = taOffset + len;
        int childBufferOffset = tmpOff + (len << 3);

        karatsuba(m, x, xOff, y, yOff, tmp, tmpOff, tmp, childBufferOffset);
        karatsuba(n1, x, xOff + m, y, yOff + m, tmp, z2Offset, tmp, childBufferOffset);

        for (int i = 0; i < n1; i++)
        {
            long loa = (i < m) ? x[xOff + i] : 0;
            long lob = (i < m) ? y[yOff + i] : 0;
            tmp[taOffset + i] = loa ^ x[xOff + m + i];
            tmp[tbOffset + i] = lob ^ y[yOff + m + i];
        }

        karatsuba(n1, tmp, taOffset, tmp, tbOffset, tmp, zMidOffset, tmp, childBufferOffset);

        System.arraycopy(tmp, tmpOff, zz, zzOff, mx2);
        System.arraycopy(tmp, z2Offset, zz, zzOff + mx2, n1x2);

        for (int i = 0; i < 2 * n1; i++)
        {
            long z0i = (i < mx2) ? tmp[tmpOff + i] : 0;
            long z2i = (i < n1x2) ? tmp[z2Offset + i] : 0;
            zz[zzOff + m + i] ^= tmp[zMidOffset + i] ^ z0i ^ z2i;
        }
    }

    /**
     * Reduces a polynomial modulo {@code X^n - 1}.
     */
    private void reduce(long[] tt, long[] z)
    {
        int partialBits = bits & 63;
        int excessBits = 64 - partialBits;
        long partialMask = -1L >>> excessBits;

//        long c =
        Nat.shiftUpBits64(size, tt, size, excessBits, tt[size - 1], z, 0);
//        assert c == 0L;
        addTo(tt, z);
        z[size - 1] &= partialMask;
    }

    /**
     * Carryless multiply of x and y, accumulating the result at z[zOff..zOff + 1], using u as a temporary buffer.
     */
    private static void implMulwAcc(long[] u, long x, long y, long[] z, int zOff)
    {
        long h = 0, m = x, n = y;
        
//      u[0] = 0;
        u[1] = y;
        for (int i = 2; i < 16; i += 2)
        {
            u[i    ] = u[i >>> 1] << 1;
            u[i + 1] = u[i      ] ^  y;

            // Interleave "repair" steps here for performance
            m = (m & 0xFEFEFEFEFEFEFEFEL) >>> 1;
            h ^= m & (n >> 63);
            n <<= 1;
        }

        int j = (int)x;
        long g, l = u[j & 15]
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

//        assert h >>> 63 == 0;

        z[zOff    ] ^= l;
        z[zOff + 1] ^= h;
    }
}
