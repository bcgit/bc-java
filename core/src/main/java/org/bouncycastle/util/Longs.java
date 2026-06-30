package org.bouncycastle.util;

import org.bouncycastle.math.raw.Nat;

/**
 * Utility methods and constants for longs.
 */
public class Longs
{
    public static final int BYTES = 8;
    public static final int SIZE = Long.SIZE;

    public static int bitCount(long i)
    {
        return Long.bitCount(i);
    }

    public static int bitLength(long i)
    {
        return SIZE - numberOfLeadingZeros(i);
    }

    public static int compare(long x, long y)
    {
        return Long.compare(x, y);
    }

    public static int compareUnsigned(long x, long y)
    {
        return Long.compareUnsigned(x, y);
    }

    public static long divideUnsigned(long x, long y)
    {
        return Long.divideUnsigned(x, y);
    }

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

    public static long parseUnsignedLong(String s)
    {
        return Long.parseUnsignedLong(s);
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

    /**
     * @deprecated Use {@link Nat#xorTo64(int, long[], int, long[], int)} instead.
     */
    public static void xorTo(int len, long[] x, int xOff, long[] z, int zOff)
    {
        Nat.xorTo64(len, x, xOff, z, zOff);
    }
}
