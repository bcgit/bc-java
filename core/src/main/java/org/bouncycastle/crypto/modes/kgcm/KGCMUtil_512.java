package org.bouncycastle.crypto.modes.kgcm;

import org.bouncycastle.math.raw.Interleave;

/**
 * Utilities for the GF(2^m) field with corresponding extension polynomial:
 *
 * GF (2^512) -> x^512 + x^8 + x^5 + x^2 + 1
 * 
 * The representation is little-endian arrays of 64-bit words
 */
public class KGCMUtil_512
{
    public static final int SIZE = 8;

    public static void add(long[] x, long[] y, long[] z)
    {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
        z[3] = x[3] ^ y[3];
        z[4] = x[4] ^ y[4];
        z[5] = x[5] ^ y[5];
        z[6] = x[6] ^ y[6];
        z[7] = x[7] ^ y[7];
    }

    public static void copy(long[] x, long[] z)
    {
        z[0] = x[0];
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
        z[4] = x[4];
        z[5] = x[5];
        z[6] = x[6];
        z[7] = x[7];
    }

    public static boolean equal(long[] x, long[] y)
    {
        long d = 0L;
        d |= x[0] ^ y[0];
        d |= x[1] ^ y[1];
        d |= x[2] ^ y[2];
        d |= x[3] ^ y[3];
        d |= x[4] ^ y[4];
        d |= x[5] ^ y[5];
        d |= x[6] ^ y[6];
        d |= x[7] ^ y[7];
        return d == 0L;
    }

    public static void multiply(long[] x, long[] y, long[] z)
    {
        long y0 = y[0], y1 = y[1], y2 = y[2], y3 = y[3];
        long y4 = y[4], y5 = y[5], y6 = y[6], y7 = y[7];
        long z0 = 0, z1 = 0, z2 = 0, z3 = 0;
        long z4 = 0, z5 = 0, z6 = 0, z7 = 0;
        long z8 = 0;

        for (int i = 0; i < 8; i += 2)
        {
            long x0 = x[i], x1 = x[i + 1];

            for (int j = 0; j < 64; ++j)
            {
                long m0 = -(x0 & 1L); x0 >>>= 1;
                z0 ^= (y0 & m0);
                z1 ^= (y1 & m0);
                z2 ^= (y2 & m0);
                z3 ^= (y3 & m0);
                z4 ^= (y4 & m0);
                z5 ^= (y5 & m0);
                z6 ^= (y6 & m0);
                z7 ^= (y7 & m0);

                long m1 = -(x1 & 1L); x1 >>>= 1;
                z1 ^= (y0 & m1);
                z2 ^= (y1 & m1);
                z3 ^= (y2 & m1);
                z4 ^= (y3 & m1);
                z5 ^= (y4 & m1);
                z6 ^= (y5 & m1);
                z7 ^= (y6 & m1);
                z8 ^= (y7 & m1);

                long c = y7 >> 63;
                y7 = (y7 << 1) | (y6 >>> 63);
                y6 = (y6 << 1) | (y5 >>> 63);
                y5 = (y5 << 1) | (y4 >>> 63);
                y4 = (y4 << 1) | (y3 >>> 63);
                y3 = (y3 << 1) | (y2 >>> 63);
                y2 = (y2 << 1) | (y1 >>> 63);
                y1 = (y1 << 1) | (y0 >>> 63);
                y0 = (y0 << 1) ^ (c & 0x125L);
            }

            long y8 = y7;
            y7 = y6;
            y6 = y5;
            y5 = y4;
            y4 = y3;
            y3 = y2;
            y2 = y1;
            y1 = y0 ^ (y8 >>> 62) ^ (y8 >>> 59) ^ (y8 >>> 56);
            y0 = y8 ^ (y8 <<   2) ^ (y8 <<   5) ^ (y8 <<   8);
        }

        z0 ^= z8 ^ (z8 <<   2) ^ (z8 <<   5) ^ (z8 <<   8);
        z1 ^=      (z8 >>> 62) ^ (z8 >>> 59) ^ (z8 >>> 56);

        z[0] = z0; z[1] = z1; z[2] = z2; z[3] = z3;
        z[4] = z4; z[5] = z5; z[6] = z6; z[7] = z7;
    }

    public static void multiplyX(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        long x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
        long m = x7 >> 63;
        z[0] = (x0 << 1) ^ (m & 0x125L);
        z[1] = (x1 << 1) | (x0 >>> 63);
        z[2] = (x2 << 1) | (x1 >>> 63);
        z[3] = (x3 << 1) | (x2 >>> 63);
        z[4] = (x4 << 1) | (x3 >>> 63);
        z[5] = (x5 << 1) | (x4 >>> 63);
        z[6] = (x6 << 1) | (x5 >>> 63);
        z[7] = (x7 << 1) | (x6 >>> 63);
    }

    public static void multiplyX8(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        long x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
        long c = x7 >>> 56;
        z[0] = (x0 << 8) ^ c ^ (c << 2) ^ (c << 5) ^ (c << 8);
        z[1] = (x1 << 8) | (x0 >>> 56);
        z[2] = (x2 << 8) | (x1 >>> 56);
        z[3] = (x3 << 8) | (x2 >>> 56);
        z[4] = (x4 << 8) | (x3 >>> 56);
        z[5] = (x5 << 8) | (x4 >>> 56);
        z[6] = (x6 << 8) | (x5 >>> 56);
        z[7] = (x7 << 8) | (x6 >>> 56);
    }

    public static void one(long[] z)
    {
        z[0] = 1;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
        z[4] = 0;
        z[5] = 0;
        z[6] = 0;
        z[7] = 0;
    }

    public static void square(long[] x, long[] z)
    {
        long[] t  = new long[SIZE << 1];
        for (int i = 0; i < SIZE; ++i)
        {
            Interleave.expand64To128(x[i], t, i << 1);
        }

        int j = SIZE << 1;
        while (--j >= SIZE)
        {
            long n = t[j];
            t[j - SIZE    ] ^= n ^ (n <<   2) ^ (n <<   5) ^ (n <<   8);
            t[j - SIZE + 1] ^=     (n >>> 62) ^ (n >>> 59) ^ (n >>> 56);      
        }

        copy(t, z);
    }

    public static void x(long[] z)
    {
        z[0] = 2;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
        z[4] = 0;
        z[5] = 0;
        z[6] = 0;
        z[7] = 0;
    }

    public static void zero(long[] z)
    {
        z[0] = 0;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
        z[4] = 0;
        z[5] = 0;
        z[6] = 0;
        z[7] = 0;
    }
}
