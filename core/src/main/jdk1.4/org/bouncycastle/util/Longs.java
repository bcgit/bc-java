package org.bouncycastle.util;

import org.bouncycastle.math.raw.Bits;

public class Longs
{
    public static final int BYTES = 8;
    public static final int SIZE = 64;

    private static final byte[] DEBRUIJN_TZ = {
        0x3F, 0x00, 0x01, 0x34, 0x02, 0x06, 0x35, 0x1A, 0x03, 0x25, 0x28, 0x07, 0x21, 0x36, 0x2F, 0x1B,
        0x3D, 0x04, 0x26, 0x2D, 0x2B, 0x29, 0x15, 0x08, 0x17, 0x22, 0x3A, 0x37, 0x30, 0x11, 0x1C, 0x0A,
        0x3E, 0x33, 0x05, 0x19, 0x24, 0x27, 0x20, 0x2E, 0x3C, 0x2C, 0x2A, 0x14, 0x16, 0x39, 0x10, 0x09,
        0x32, 0x18, 0x23, 0x1F, 0x3B, 0x13, 0x38, 0x0F, 0x31, 0x1E, 0x12, 0x0E, 0x1D, 0x0D, 0x0C, 0x0B };

    public static long highestOneBit(long i)
    {
        i |= (i >>  1);
        i |= (i >>  2);
        i |= (i >>  4);
        i |= (i >>  8);
        i |= (i >> 16);
        i |= (i >> 32);
        return i - (i >>> 1);
    }

    public static long lowestOneBit(long i)
    {
        return i & -i;
    }

    public static int numberOfLeadingZeros(long i)
    {
        int x = (int)(i >>> 32), n = 0;
        if (x == 0)
        {
            n = 32;
            x = (int)i;
        }
        return n + Integers.numberOfLeadingZeros(x);
    }

    public static int numberOfTrailingZeros(long i)
    {
        int n = DEBRUIJN_TZ[(int)(((i & -i) * 0x045FBAC7992A70DAL) >>> 58)];
        long m = (((i & 0xFFFFFFFFL) | (i >>> 32)) - 1L) >> 63;
        return n - (int)m;
    }

    public static long reverse(long i)
    {
        i = Bits.bitPermuteStepSimple(i, 0x5555555555555555L, 1);
        i = Bits.bitPermuteStepSimple(i, 0x3333333333333333L, 2);
        i = Bits.bitPermuteStepSimple(i, 0x0F0F0F0F0F0F0F0FL, 4);
        return reverseBytes(i);
    }

    public static long reverseBytes(long i)
    {
        return rotateLeft(i & 0xFF000000FF000000L,  8) |
               rotateLeft(i & 0x00FF000000FF0000L, 24) |
               rotateLeft(i & 0x0000FF000000FF00L, 40) |
               rotateLeft(i & 0x000000FF000000FFL, 56);
    }

    public static long rotateLeft(long i, int distance)
    {
        return (i << distance) | (i >>> -distance);
    }

    public static long rotateRight(long i, int distance)
    {
        return (i >>> distance) | (i << -distance);
    }

    public static Long valueOf(long value)
    {
        return new Long(value);
    }
}
