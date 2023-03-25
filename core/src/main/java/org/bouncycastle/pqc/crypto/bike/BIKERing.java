package org.bouncycastle.pqc.crypto.bike;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

class BIKERing
{
    private static final int PERMUTATION_CUTOFF = 64;

    private final int bits;
    private final int size;
    private final int sizeExt;
    private final Map<Integer, Integer> halfPowers = new HashMap<Integer, Integer>();

    BIKERing(int r)
    {
        if ((r & 0xFFFF0001) != 1)
            throw new IllegalArgumentException();

        bits = r;
        size = (r + 63) >>> 6;
        sizeExt = size * 2;

        generateHalfPowersInv(halfPowers, r);
    }

    void add(long[] x, long[] y, long[] z)
    {
        for (int i = 0; i < size; ++i)
        {
            z[i] = x[i] ^ y[i];
        }
    }

    void addTo(long[] x, long[] z)
    {
        for (int i = 0; i < size; ++i)
        {
            z[i] ^= x[i];
        }
    }

    void copy(long[] x, long[] z)
    {
        for (int i = 0; i < size; ++i)
        {
            z[i] = x[i];
        }
    }

    long[] create()
    {
        return new long[size];
    }

    long[] createExt()
    {
        return new long[sizeExt];
    }

    void decodeBytes(byte[] bs, long[] z)
    {
        int partialBits = bits & 63;
        Pack.littleEndianToLong(bs, 0, z, 0, size - 1);
        byte[] last = new byte[8];
        System.arraycopy(bs, (size - 1) << 3, last, 0, (partialBits + 7) >>> 3);
        z[size - 1] = Pack.littleEndianToLong(last, 0);
//        assert (z[Size - 1] >> partialBits) == 0L;
    }

    byte[] encodeBitsTransposed(long[] x)
    {
        byte[] bs = new byte[bits];
        bs[0] = (byte)(x[0] & 1L);
        for (int i = 1; i < bits; ++i)
        {
            bs[bits - i] = (byte)((x[i >>> 6] >>> (i & 63)) & 1L);
        }
        return bs;
    }

    void encodeBytes(long[] x, byte[] bs)
    {
        int partialBits = bits & 63;
//        assert (x[size - 1] >>> partialBits) == 0L;
        Pack.longToLittleEndian(x, 0, size - 1, bs, 0);
        byte[] last = new byte[8];
        Pack.longToLittleEndian(x[size - 1], last, 0);
        System.arraycopy(last, 0, bs, (size - 1) << 3, (partialBits + 7) >>> 3);
    }

    void inv(long[] a, long[] z)
    {
        long[] f = create();
        long[] g = create();
        long[] t = create();

        copy(a, f);
        copy(a, t);

        int rSub2 = bits - 2;
        int bits = 32 - Integers.numberOfLeadingZeros(rSub2);

        for (int i = 1; i < bits; ++i)
        {
            squareN(f, 1 << (i - 1), g);
            multiply(f, g, f);

            if ((rSub2 & (1 << i)) != 0)
            {
                int n = rSub2 & ((1 << i) - 1);
                squareN(f, n, g);
                multiply(t, g, t);
            }
        }

        square(t, z);
    }

    void multiply(long[] x, long[] y, long[] z)
    {
        long[] tt = createExt();
        implMultiplyAcc(x, y, tt);
        reduce(tt, z);
    }

    void reduce(long[] tt, long[] z)
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

    int getSize()
    {
        return size;
    }

    int getSizeExt()
    {
        return sizeExt;
    }

    void square(long[] x, long[] z)
    {
        long[] tt = createExt();
        implSquare(x, tt);
        reduce(tt, z);
    }

    void squareN(long[] x, int n, long[] z)
    {
//        assert n > 0;

        /*
         * In these polynomial rings, 'squareN' for some 'n' is equivalent to a fixed permutation of the
         * coefficients. Calls to 'inv' generate calls to 'squareN' with a predictable sequence of 'n' values.
         * For such 'n' above some cutoff value, we precalculate a small constant and then apply the permutation in
         * place of explicit squaring for that 'n'.
         */
        if (n >= PERMUTATION_CUTOFF)
        {
            implPermute(x, n, z);
            return;
        }

        long[] tt = createExt();
        implSquare(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            implSquare(z, tt);
            reduce(tt, z);
        }
    }

    private static int implModAdd(int m, int x, int y)
    {
        int t = x + y - m;
        return t + ((t >> 31) & m);
    }

    protected void implMultiplyAcc(long[] x, long[] y, long[] zz)
    {
        long[] u = new long[16];

        // Schoolbook

//        for (int i = 0; i < size; ++i)
//        {
//            long x_i = x[i];
//
//            for (int j = 0; j < size; ++j)
//            {
//                long y_j = y[j];
//
//                implMulwAcc(u, x_i, y_j, zz, i + j);
//            }
//        }

        // Arbitrary-degree Karatsuba

        for (int i = 0; i < size; ++i)
        {
            implMulwAcc(u, x[i], y[i], zz, i << 1);
        }

        long v0 = zz[0], v1 = zz[1];
        for (int i = 1; i < size; ++i)
        {
            v0 ^= zz[i << 1]; zz[i] = v0 ^ v1; v1 ^= zz[(i << 1) + 1];
        }

        long w = v0 ^ v1;
        for (int i = 0; i < size; ++i)
        {
            zz[size + i] = zz[i] ^ w;
        }

        int last = size - 1;
        for (int zPos = 1; zPos < (last * 2); ++zPos)
        {
            int hi = Math.min(last, zPos);
            int lo = zPos - hi;

            while (lo < hi)
            {
                implMulwAcc(u, x[lo] ^ x[hi], y[lo] ^ y[hi], zz, zPos);

                ++lo;
                --hi;
            }
        }
    }

    private void implPermute(long[] x, int n, long[] z)
    {
        int r = bits;

        int pow_1 = ((Integer)halfPowers.get(Integers.valueOf(n))).intValue();
        int pow_2 = implModAdd(r, pow_1, pow_1);
        int pow_4 = implModAdd(r, pow_2, pow_2);
        int pow_8 = implModAdd(r, pow_4, pow_4);

        int p0 = r - pow_8;
        int p1 = implModAdd(r, p0, pow_1);
        int p2 = implModAdd(r, p0, pow_2);
        int p3 = implModAdd(r, p1, pow_2);
        int p4 = implModAdd(r, p0, pow_4);
        int p5 = implModAdd(r, p1, pow_4);
        int p6 = implModAdd(r, p2, pow_4);
        int p7 = implModAdd(r, p3, pow_4);

        for (int i = 0; i < size; ++i)
        {
            long z_i = 0;

            for (int j = 0; j < 64; j += 8)
            {
                p0 = implModAdd(r, p0, pow_8);
                p1 = implModAdd(r, p1, pow_8);
                p2 = implModAdd(r, p2, pow_8);
                p3 = implModAdd(r, p3, pow_8);
                p4 = implModAdd(r, p4, pow_8);
                p5 = implModAdd(r, p5, pow_8);
                p6 = implModAdd(r, p6, pow_8);
                p7 = implModAdd(r, p7, pow_8);

                z_i |= ((x[p0 >>> 6] >>> p0) & 1L) << (j + 0);
                z_i |= ((x[p1 >>> 6] >>> p1) & 1L) << (j + 1);
                z_i |= ((x[p2 >>> 6] >>> p2) & 1L) << (j + 2);
                z_i |= ((x[p3 >>> 6] >>> p3) & 1L) << (j + 3);
                z_i |= ((x[p4 >>> 6] >>> p4) & 1L) << (j + 4);
                z_i |= ((x[p5 >>> 6] >>> p5) & 1L) << (j + 5);
                z_i |= ((x[p6 >>> 6] >>> p6) & 1L) << (j + 6);
                z_i |= ((x[p7 >>> 6] >>> p7) & 1L) << (j + 7);
            }

            z[i] = z_i;
        }

        z[size - 1] &= -1L >>> -r;
    }

    private static int generateHalfPower(int r, int r32, int n)
    {
        int p = 1;
        int k = n;
        while (k >= 32)
        {
            int y = r32 * p;
            long t = (y & 0xFFFFFFFFL) * r;
            long u = t + p;
//            assert (int)u == 0;
            p = (int)(u >>> 32);
            k -= 32;
        }
        if (k > 0)
        {
            int mk = -1 >>> -k;
            int y = (r32 * p) & mk;
            long t = (y & 0xFFFFFFFFL) * r;
            long u = t + p;
//            assert ((int)u & mk) == 0;
            p = (int)(u >>> k);
        }
        return p;
    }

    private static void generateHalfPowersInv(Map<Integer, Integer> halfPowers, int r)
    {
        int rSub2 = r - 2;
        int bits = 32 - Integers.numberOfLeadingZeros(rSub2);

        int r32 = Mod.inverse32(-r);
        for (int i = 1; i < bits; ++i)
        {
            int m = 1 << (i - 1);
            if (m >= PERMUTATION_CUTOFF && !halfPowers.containsKey(Integers.valueOf(m)))
            {
                halfPowers.put(Integers.valueOf(m), Integers.valueOf(generateHalfPower(r, r32, m)));
            }

            if ((rSub2 & (1 << i)) != 0)
            {
                int n = rSub2 & ((1 << i) - 1);
                if (n >= PERMUTATION_CUTOFF && !halfPowers.containsKey(Integers.valueOf(n)))
                {
                    halfPowers.put(Integers.valueOf(n),  Integers.valueOf(generateHalfPower(r, r32, n)));
                }
            }
        }
    }

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

    private void implSquare(long[] x, long[] zz)
    {
        Interleave.expand64To128(x, 0, size, zz, 0);
    }
}
