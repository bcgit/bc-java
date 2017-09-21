package org.bouncycastle.crypto.modes.kgcm;

/**
 * Utilities for the GF(2^m) field with corresponding extension polynomial:
 *
 * GF (2^256) -> x^256 + x^10 + x^5 + x^2 + 1
 * 
 * The representation is little-endian arrays of 64-bit words
*/
public class KGCMUtil_256
{
    public static final int SIZE = 4;

    public static void add(long[] x, long[] y, long[] z)
    {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
        z[3] = x[3] ^ y[3];
    }

    public static void copy(long[] x, long[] z)
    {
        z[0] = x[0];
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
    }

    public static void double1x(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        long m = x3 >> 63;
        z[0] = (x0 << 1) ^ (m & 0x425L);
        z[1] = (x1 << 1) | (x0 >>> 63);
        z[2] = (x2 << 1) | (x1 >>> 63);
        z[3] = (x3 << 1) | (x2 >>> 63);
    }

    public static void double8x(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        long c = x3 >>> 56;
        z[0] = (x0 << 8) ^ c ^ (c << 2) ^ (c << 5) ^ (c << 10);
        z[1] = (x1 << 8) | (x0 >>> 56);
        z[2] = (x2 << 8) | (x1 >>> 56);
        z[3] = (x3 << 8) | (x2 >>> 56);
    }

    public static boolean equal(long[] x, long[] y)
    {
        long d = 0L;
        d |= x[0] ^ y[0];
        d |= x[1] ^ y[1];
        d |= x[2] ^ y[2];
        d |= x[3] ^ y[3];
        return d == 0L;
    }

    public static void multiply(long[] x, long[] y, long[] z)
    {
        long y0 = y[0], y1 = y[1], y2 = y[2], y3 = y[3];
        long z0 = 0, z1 = 0, z2 = 0, z3 = 0;

        for (int i = 0; i < 4; ++i)
        {
            long bits = x[i];
            for (int j = 0; j < 64; ++j)
            {
                long m1 = -(bits & 1L); bits >>= 1;
                z0 ^= (y0 & m1);
                z1 ^= (y1 & m1);
                z2 ^= (y2 & m1);
                z3 ^= (y3 & m1);

                long m2 = y3 >> 63;
                y3 = (y3 << 1) | (y2 >>> 63);
                y2 = (y2 << 1) | (y1 >>> 63);
                y1 = (y1 << 1) | (y0 >>> 63);
                y0 = (y0 << 1) ^ (m2 & 0x425L);
            }
        }

        z[0] = z0; z[1] = z1; z[2] = z2; z[3] = z3;
    }

    public static void one(long[] z)
    {
        z[0] = 1;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
    }

    public static void zero(long[] z)
    {
        z[0] = 0;
        z[1] = 0;
        z[2] = 0;
        z[3] = 0;
    }
}
