package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

public abstract class GCMUtil
{
    private static final int E1 = 0xe1000000;
    private static final long E1L = (E1 & 0xFFFFFFFFL) << 32;

    public static byte[] oneAsBytes()
    {
        byte[] tmp = new byte[16];
        tmp[0] = (byte)0x80;
        return tmp;
    }

    public static int[] oneAsInts()
    {
        int[] tmp = new int[4];
        tmp[0] = 1 << 31;
        return tmp;
    }

    public static long[] oneAsLongs()
    {
        long[] tmp = new long[2];
        tmp[0] = 1L << 63;
        return tmp;
    }

    public static byte[] asBytes(int[] x)
    {
        byte[] z = new byte[16];
        Pack.intToBigEndian(x, z, 0);
        return z;
    }

    public static void asBytes(int[] x, byte[] z)
    {
        Pack.intToBigEndian(x, z, 0);
    }

    public static byte[] asBytes(long[] x)
    {
        byte[] z = new byte[16];
        Pack.longToBigEndian(x, z, 0);
        return z;
    }

    public static void asBytes(long[] x, byte[] z)
    {
        Pack.longToBigEndian(x, z, 0);
    }

    public static int[] asInts(byte[] x)
    {
        int[] z = new int[4];
        Pack.bigEndianToInt(x, 0, z);
        return z;
    }

    public static void asInts(byte[] x, int[] z)
    {
        Pack.bigEndianToInt(x, 0, z);
    }

    public static long[] asLongs(byte[] x)
    {
        long[] z = new long[2];
        Pack.bigEndianToLong(x, 0, z);
        return z;
    }

    public static void asLongs(byte[] x, long[] z)
    {
        Pack.bigEndianToLong(x, 0, z);
    }

    public static void copy(int[] x, int[] z)
    {
        z[0] = x[0];
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
    }

    public static void copy(long[] x, long[] z)
    {
        z[0] = x[0];
        z[1] = x[1];
    }

    public static void divideP(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1];
        long m = x0 >> 63;
        x0 ^= (m & E1L);
        z[0] = (x0 << 1) | (x1 >>> 63);
        z[1] = (x1 << 1) | -m;
    }

    public static void multiply(byte[] x, byte[] y)
    {
        long[] t1 = GCMUtil.asLongs(x);
        long[] t2 = GCMUtil.asLongs(y);
        GCMUtil.multiply(t1, t2);
        GCMUtil.asBytes(t1, x);
    }

    public static void multiply(int[] x, int[] y)
    {
        int y0 = y[0], y1 = y[1], y2 = y[2], y3 = y[3];
        int z0 = 0, z1 = 0, z2 = 0, z3 = 0;

        for (int i = 0; i < 4; ++i)
        {
            int bits = x[i];
            for (int j = 0; j < 32; ++j)
            {
                int m1 = bits >> 31; bits <<= 1;
                z0 ^= (y0 & m1);
                z1 ^= (y1 & m1);
                z2 ^= (y2 & m1);
                z3 ^= (y3 & m1);

                int m2 = (y3 << 31) >> 8;
                y3 = (y3 >>> 1) | (y2 << 31);
                y2 = (y2 >>> 1) | (y1 << 31);
                y1 = (y1 >>> 1) | (y0 << 31);
                y0 = (y0 >>> 1) ^ (m2 & E1);
            }
        }

        x[0] = z0;
        x[1] = z1;
        x[2] = z2;
        x[3] = z3;
    }

    public static void multiply(long[] x, long[] y)
    {
//        long x0 = x[0], x1 = x[1];
//        long y0 = y[0], y1 = y[1];
//        long z0 = 0, z1 = 0, z2 = 0;
//
//        for (int j = 0; j < 64; ++j)
//        {
//            long m0 = x0 >> 63; x0 <<= 1;
//            z0 ^= (y0 & m0);
//            z1 ^= (y1 & m0);
//
//            long m1 = x1 >> 63; x1 <<= 1;
//            z1 ^= (y0 & m1);
//            z2 ^= (y1 & m1);
//
//            long c = (y1 << 63) >> 8;
//            y1 = (y1 >>> 1) | (y0 << 63);
//            y0 = (y0 >>> 1) ^ (c & E1L);
//        }
//
//        z0 ^= z2 ^ (z2 >>>  1) ^ (z2 >>>  2) ^ (z2 >>>  7);
//        z1 ^=      (z2 <<  63) ^ (z2 <<  62) ^ (z2 <<  57);
//
//        x[0] = z0;
//        x[1] = z1;

        /*
         * "Three-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
         *
         * Without access to the high part of a 64x64 product x * y, we use a bit reversal to calculate it:
         *     rev(x) * rev(y) == rev((x * y) << 1) 
         */

        long x0 = x[0], x1 = x[1];
        long y0 = y[0], y1 = y[1];
        long x0r = Longs.reverse(x0), x1r = Longs.reverse(x1);
        long y0r = Longs.reverse(y0), y1r = Longs.reverse(y1);

        long h0  = Longs.reverse(implMul64(x0r, y0r));
        long h1  = implMul64(x0, y0) << 1;
        long h2  = Longs.reverse(implMul64(x1r, y1r));
        long h3  = implMul64(x1, y1) << 1;
        long h4  = Longs.reverse(implMul64(x0r ^ x1r, y0r ^ y1r));
        long h5  = implMul64(x0 ^ x1, y0 ^ y1) << 1;

        long z0  = h0;
        long z1  = h1 ^ h0 ^ h2 ^ h4;
        long z2  = h2 ^ h1 ^ h3 ^ h5;
        long z3  = h3;

        z1 ^= z3 ^ (z3 >>>  1) ^ (z3 >>>  2) ^ (z3 >>>  7);
//      z2 ^=      (z3 <<  63) ^ (z3 <<  62) ^ (z3 <<  57);
        z2 ^=                    (z3 <<  62) ^ (z3 <<  57);

        z0 ^= z2 ^ (z2 >>>  1) ^ (z2 >>>  2) ^ (z2 >>>  7);
        z1 ^=      (z2 <<  63) ^ (z2 <<  62) ^ (z2 <<  57);

        x[0] = z0;
        x[1] = z1;
    }

    public static void multiplyP(int[] x)
    {
        int x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        int m = (x3 << 31) >> 31;
        x[0] = (x0 >>> 1) ^ (m & E1);
        x[1] = (x1 >>> 1) | (x0 << 31);
        x[2] = (x2 >>> 1) | (x1 << 31);
        x[3] = (x3 >>> 1) | (x2 << 31);
    }

    public static void multiplyP(int[] x, int[] z)
    {
        int x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        int m = (x3 << 31) >> 31;
        z[0] = (x0 >>> 1) ^ (m & E1);
        z[1] = (x1 >>> 1) | (x0 << 31);
        z[2] = (x2 >>> 1) | (x1 << 31);
        z[3] = (x3 >>> 1) | (x2 << 31);
    }

    public static void multiplyP(long[] x)
    {
        long x0 = x[0], x1 = x[1];
        long m = (x1 << 63) >> 63;
        x[0] = (x0 >>> 1) ^ (m & E1L);
        x[1] = (x1 >>> 1) | (x0 << 63);
    }

    public static void multiplyP(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1];
        long m = (x1 << 63) >> 63;
        z[0] = (x0 >>> 1) ^ (m & E1L);
        z[1] = (x1 >>> 1) | (x0 << 63);
    }

    public static void multiplyP3(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1];
        long c = x1 << 61;
        z[0] = (x0 >>> 3) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        z[1] = (x1 >>> 3) | (x0 << 61);
    }

    public static void multiplyP4(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1];
        long c = x1 << 60;
        z[0] = (x0 >>> 4) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        z[1] = (x1 >>> 4) | (x0 << 60);
    }

    public static void multiplyP7(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1];
        long c = x1 << 57;
        z[0] = (x0 >>> 7) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        z[1] = (x1 >>> 7) | (x0 << 57);
    }

    public static void multiplyP8(int[] x)
    {
        int x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        int c = x3 << 24;
        x[0] = (x0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        x[1] = (x1 >>> 8) | (x0 << 24);
        x[2] = (x2 >>> 8) | (x1 << 24);
        x[3] = (x3 >>> 8) | (x2 << 24);
    }

    public static void multiplyP8(int[] x, int[] y)
    {
        int x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
        int c = x3 << 24;
        y[0] = (x0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        y[1] = (x1 >>> 8) | (x0 << 24);
        y[2] = (x2 >>> 8) | (x1 << 24);
        y[3] = (x3 >>> 8) | (x2 << 24);
    }

    public static void multiplyP8(long[] x)
    {
        long x0 = x[0], x1 = x[1];
        long c = x1 << 56;
        x[0] = (x0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        x[1] = (x1 >>> 8) | (x0 << 56);
    }

    public static void multiplyP8(long[] x, long[] y)
    {
        long x0 = x[0], x1 = x[1];
        long c = x1 << 56;
        y[0] = (x0 >>> 8) ^ c ^ (c >>> 1) ^ (c >>> 2) ^ (c >>> 7);
        y[1] = (x1 >>> 8) | (x0 << 56);
    }

    public static long[] pAsLongs()
    {
        long[] tmp = new long[2];
        tmp[0] = 1L << 62;
        return tmp;
    }

    public static void square(long[] x, long[] z)
    {
        long[] t  = new long[4];
        Interleave.expand64To128Rev(x[0], t, 0);
        Interleave.expand64To128Rev(x[1], t, 2);

        long z0 = t[0], z1 = t[1], z2 = t[2], z3 = t[3];

        z1 ^= z3 ^ (z3 >>>  1) ^ (z3 >>>  2) ^ (z3 >>>  7);
        z2 ^=      (z3 <<  63) ^ (z3 <<  62) ^ (z3 <<  57);

        z0 ^= z2 ^ (z2 >>>  1) ^ (z2 >>>  2) ^ (z2 >>>  7);
        z1 ^=      (z2 <<  63) ^ (z2 <<  62) ^ (z2 <<  57);

        z[0] = z0;
        z[1] = z1;
    }

    public static void xor(byte[] x, byte[] y)
    {
        int i = 0;
        do
        {
            x[i] ^= y[i]; ++i;
            x[i] ^= y[i]; ++i;
            x[i] ^= y[i]; ++i;
            x[i] ^= y[i]; ++i;
        }
        while (i < 16);
    }

    public static void xor(byte[] x, byte[] y, int yOff)
    {
        int i = 0;
        do
        {
            x[i] ^= y[yOff + i]; ++i;
            x[i] ^= y[yOff + i]; ++i;
            x[i] ^= y[yOff + i]; ++i;
            x[i] ^= y[yOff + i]; ++i;
        }
        while (i < 16);
    }

    public static void xor(byte[] x, int xOff, byte[] y, int yOff, byte[] z, int zOff)
    {
        int i = 0;
        do
        {
            z[zOff + i] = (byte)(x[xOff + i] ^ y[yOff + i]); ++i;
            z[zOff + i] = (byte)(x[xOff + i] ^ y[yOff + i]); ++i;
            z[zOff + i] = (byte)(x[xOff + i] ^ y[yOff + i]); ++i;
            z[zOff + i] = (byte)(x[xOff + i] ^ y[yOff + i]); ++i;
        }
        while (i < 16);
    }

    public static void xor(byte[] x, byte[] y, int yOff, int yLen)
    {
        while (--yLen >= 0)
        {
            x[yLen] ^= y[yOff + yLen];
        }
    }

    public static void xor(byte[] x, int xOff, byte[] y, int yOff, int len)
    {
        while (--len >= 0)
        {
            x[xOff + len] ^= y[yOff + len];
        }
    }

    public static void xor(byte[] x, byte[] y, byte[] z)
    {
        int i = 0;
        do
        {
            z[i] = (byte)(x[i] ^ y[i]); ++i;
            z[i] = (byte)(x[i] ^ y[i]); ++i;
            z[i] = (byte)(x[i] ^ y[i]); ++i;
            z[i] = (byte)(x[i] ^ y[i]); ++i;
        }
        while (i < 16);
    }

    public static void xor(int[] x, int[] y)
    {
        x[0] ^= y[0];
        x[1] ^= y[1];
        x[2] ^= y[2];
        x[3] ^= y[3];
    }

    public static void xor(int[] x, int[] y, int[] z)
    {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
        z[3] = x[3] ^ y[3];
    }

    public static void xor(long[] x, long[] y)
    {
        x[0] ^= y[0];
        x[1] ^= y[1];
    }

    public static void xor(long[] x, long[] y, long[] z)
    {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
    }

    private static long implMul64(long x, long y)
    {
        long x0 = x & 0x1111111111111111L;
        long x1 = x & 0x2222222222222222L;
        long x2 = x & 0x4444444444444444L;
        long x3 = x & 0x8888888888888888L;

        long y0 = y & 0x1111111111111111L;
        long y1 = y & 0x2222222222222222L;
        long y2 = y & 0x4444444444444444L;
        long y3 = y & 0x8888888888888888L;

        long z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
        long z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
        long z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
        long z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);

        z0 &= 0x1111111111111111L;
        z1 &= 0x2222222222222222L;
        z2 &= 0x4444444444444444L;
        z3 &= 0x8888888888888888L;

        return z0 | z1 | z2 | z3;
    }
}
