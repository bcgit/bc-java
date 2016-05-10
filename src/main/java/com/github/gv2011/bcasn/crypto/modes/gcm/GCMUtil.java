package com.github.gv2011.bcasn.crypto.modes.gcm;

import com.github.gv2011.bcasn.util.Pack;

public abstract class GCMUtil
{
    private static final int E1 = 0xe1000000;
    private static final long E1L = (E1 & 0xFFFFFFFFL) << 32;

    private static int[] generateLookup()
    {
        int[] lookup = new int[256];

        for (int c = 0; c < 256; ++c)
        {
            int v = 0;
            for (int i = 7; i >= 0; --i)
            {
                if ((c & (1 << i)) != 0)
                {
                    v ^= (E1 >>> (7 - i));
                }
            }
            lookup[c] = v;
        }

        return lookup;
    }

    private static final int[] LOOKUP = generateLookup();

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

    public static void multiply(byte[] x, byte[] y)
    {
        int[] t1 = GCMUtil.asInts(x);
        int[] t2 = GCMUtil.asInts(y);
        GCMUtil.multiply(t1, t2);
        GCMUtil.asBytes(t1, x);
    }

    public static void multiply(int[] x, int[] y)
    {
        int r00 = x[0], r01 = x[1], r02 = x[2], r03 = x[3];
        int r10 = 0, r11 = 0, r12 = 0, r13 = 0;
        
        for (int i = 0; i < 4; ++i)
        {
            int bits = y[i];
            for (int j = 0; j < 32; ++j)
            {
                int m1 = bits >> 31; bits <<= 1;
                r10 ^= (r00 & m1);
                r11 ^= (r01 & m1);
                r12 ^= (r02 & m1);
                r13 ^= (r03 & m1);

                int m2 = (r03 << 31) >> 8;
                r03 = (r03 >>> 1) | (r02 << 31);
                r02 = (r02 >>> 1) | (r01 << 31);
                r01 = (r01 >>> 1) | (r00 << 31);
                r00 = (r00 >>> 1) ^ (m2 & E1);
            }
        }

        x[0] = r10;
        x[1] = r11;
        x[2] = r12;
        x[3] = r13;
    }

    public static void multiply(long[] x, long[] y)
    {
        long r00 = x[0], r01 = x[1], r10 = 0, r11 = 0;

        for (int i = 0; i < 2; ++i)
        {
            long bits = y[i];
            for (int j = 0; j < 64; ++j)
            {
                long m1 = bits >> 63; bits <<= 1;
                r10 ^= (r00 & m1);
                r11 ^= (r01 & m1);

                long m2 = (r01 << 63) >> 8;
                r01 = (r01 >>> 1) | (r00 << 63);
                r00 = (r00 >>> 1) ^ (m2 & E1L);
            }
        }

        x[0] = r10;
        x[1] = r11;
    }

    // P is the value with only bit i=1 set
    public static void multiplyP(int[] x)
    {
        int m = shiftRight(x) >> 8;
        x[0] ^= (m & E1);
    }

    public static void multiplyP(int[] x, int[] z)
    {
        int m = shiftRight(x, z) >> 8;
        z[0] ^= (m & E1);
    }

    // P is the value with only bit i=1 set
    public static void multiplyP8(int[] x)
    {
//        for (int i = 8; i != 0; --i)
//        {
//            multiplyP(x);
//        }

        int c = shiftRightN(x, 8);
        x[0] ^= LOOKUP[c >>> 24];
    }

    public static void multiplyP8(int[] x, int[] y)
    {
        int c = shiftRightN(x, 8, y);
        y[0] ^= LOOKUP[c >>> 24];
    }

    static int shiftRight(int[] x)
    {
//        int c = 0;
//        for (int i = 0; i < 4; ++i)
//        {
//            int b = x[i];
//            x[i] = (b >>> 1) | c;
//            c = b << 31;
//        }
//        return c;

        int b = x[0];
        x[0] = b >>> 1;
        int c = b << 31;
        b = x[1];
        x[1] = (b >>> 1) | c;
        c = b << 31;
        b = x[2];
        x[2] = (b >>> 1) | c;
        c = b << 31;
        b = x[3];
        x[3] = (b >>> 1) | c;
        return b << 31;
    }

    static int shiftRight(int[] x, int[] z)
    {
//      int c = 0;
//      for (int i = 0; i < 4; ++i)
//      {
//          int b = x[i];
//          z[i] = (b >>> 1) | c;
//          c = b << 31;
//      }
//      return c;

        int b = x[0];
        z[0] = b >>> 1;
        int c = b << 31;
        b = x[1];
        z[1] = (b >>> 1) | c;
        c = b << 31;
        b = x[2];
        z[2] = (b >>> 1) | c;
        c = b << 31;
        b = x[3];
        z[3] = (b >>> 1) | c;
        return b << 31;
    }

    static long shiftRight(long[] x)
    {
        long b = x[0];
        x[0] = b >>> 1;
        long c = b << 63; 
        b = x[1];
        x[1] = (b >>> 1) | c;
        return b << 63;
    }

    static long shiftRight(long[] x, long[] z)
    {
        long b = x[0];
        z[0] = b >>> 1;
        long c = b << 63; 
        b = x[1];
        z[1] = (b >>> 1) | c;
        return b << 63;
    }

    static int shiftRightN(int[] x, int n)
    {
//        int c = 0, nInv = 32 - n;
//        for (int i = 0; i < 4; ++i)
//        {
//            int b = x[i];
//            x[i] = (b >>> n) | c;
//            c = b << nInv;
//        }
//        return c;

        int b = x[0], nInv = 32 - n;
        x[0] = b >>> n;
        int c = b << nInv;
        b = x[1];
        x[1] = (b >>> n) | c;
        c = b << nInv;
        b = x[2];
        x[2] = (b >>> n) | c;
        c = b << nInv;
        b = x[3];
        x[3] = (b >>> n) | c;
        return b << nInv;
    }

    static int shiftRightN(int[] x, int n, int[] z)
    {
//        int c = 0, nInv = 32 - n;
//        for (int i = 0; i < 4; ++i)
//        {
//            int b = x[i];
//            z[i] = (b >>> n) | c;
//            c = b << nInv;
//        }
//        return c;

        int b = x[0], nInv = 32 - n;
        z[0] = b >>> n;
        int c = b << nInv;
        b = x[1];
        z[1] = (b >>> n) | c;
        c = b << nInv;
        b = x[2];
        z[2] = (b >>> n) | c;
        c = b << nInv;
        b = x[3];
        z[3] = (b >>> n) | c;
        return b << nInv;
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

    public static void xor(byte[] x, byte[] y, int yOff, int yLen)
    {
        while (--yLen >= 0)
        {
            x[yLen] ^= y[yOff + yLen];
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
}
