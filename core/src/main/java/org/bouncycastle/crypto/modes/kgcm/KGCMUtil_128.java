package org.bouncycastle.crypto.modes.kgcm;

/**
 * Utilities for the GF(2^m) field with corresponding extension polynomial:
 *
 * GF (2^128) -> x^128 + x^7 + x^2 + x + 1
 * 
 * The representation is little-endian arrays of 64-bit words
*/
public class KGCMUtil_128
{
    public static final int SIZE = 2;

    public static void add(long[] x, long[] y, long[] z)
    {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
    }

    public static void copy(long[] x, long[] z)
    {
        z[0] = x[0];
        z[1] = x[1];
    }

    public static boolean equal(long[] x, long[] y)
    {
        long d = 0L;
        d |= x[0] ^ y[0];
        d |= x[1] ^ y[1];
        return d == 0L;
    }

    public static void multiply(long[] x, long[] y, long[] z)
    {
        long y0 = y[0], y1 = y[1];
        long z0 = 0, z1 = 0;

        for (int i = 0; i < 2; ++i)
        {
            long bits = x[i];
            for (int j = 0; j < 64; ++j)
            {
                long m1 = -(bits & 1L); bits >>= 1;
                z0 ^= (y0 & m1);
                z1 ^= (y1 & m1);

                long m2 = y1 >> 63;
                y1 = (y1 << 1) | (y0 >>> 63);
                y0 = (y0 << 1) ^ (m2 & 0x87L);
            }
        }

        z[0] = z0; z[1] = z1;
    }

    public static void multiplyX(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1];
        long m = x1 >> 63;
        z[0] = (x0 << 1) ^ (m & 0x87L);
        z[1] = (x1 << 1) | (x0 >>> 63);
    }

    public static void multiplyX8(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1];
        long c = x1 >>> 56;
        z[0] = (x0 << 8) ^ c ^ (c << 1) ^ (c << 2) ^ (c << 7);
        z[1] = (x1 << 8) | (x0 >>> 56);
    }

    public static void one(long[] z)
    {
        z[0] = 1;
        z[1] = 0;
    }

    public static void zero(long[] z)
    {
        z[0] = 0;
        z[1] = 0;
    }
}
