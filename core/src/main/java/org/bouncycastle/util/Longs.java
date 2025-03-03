package org.bouncycastle.util;

/**
 * Utility methods and constants for longs.
 */
public class Longs
{
    public static final int BYTES = 8;
    public static final int SIZE = Long.SIZE;

    public static long highestOneBit(long i)
    {
        return Long.highestOneBit(i);
    }

    public static long lowestOneBit(long i)
    {
        return Long.lowestOneBit(i);
    }

    public static int numberOfLeadingZeros(long i)
    {
        return Long.numberOfLeadingZeros(i);
    }

    public static int numberOfTrailingZeros(long i)
    {
        return Long.numberOfTrailingZeros(i);
    }

    public static long reverse(long i)
    {
        return Long.reverse(i);
    }

    public static long reverseBytes(long i)
    {
        return Long.reverseBytes(i);
    }

    public static long rotateLeft(long i, int distance)
    {
        return Long.rotateLeft(i, distance);
    }

    public static long rotateRight(long i, int distance)
    {
        return Long.rotateRight(i, distance);
    }

    public static Long valueOf(long value)
    {
        return Long.valueOf(value);
    }

    public static void xorTo(int len, long[] x, int xOff, long[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff + i] ^= x[xOff + i];
        }
    }
}
