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
        // @since 1.7
//        return Long.compare(x, y);
        return x < y ? -1 : x == y ? 0 : 1;
    }

    public static int compareUnsigned(long x, long y)
    {
//        return Long.compareUnsigned(x, y);
        return compare(x + Long.MIN_VALUE, y + Long.MIN_VALUE);
    }

    public static long divideUnsigned(long dividend, long divisor)
    {
        // @since 1.8
//        return Long.divideUnsigned(dividend, divisor);
        if (divisor < 0L)
        {
            // divisor > Long.MAX_VALUE (unsigned): quotient is 0 or 1.
            return compareUnsigned(dividend, divisor) < 0 ? 0L : 1L;
        }
        if (dividend >= 0L)
        {
            return dividend / divisor;
        }
        // Approximate, then correct (Hacker's Delight 9-3 / Guava UnsignedLongs).
        long quotient = ((dividend >>> 1) / divisor) << 1;
        long rem = dividend - quotient * divisor;
        return quotient + (compareUnsigned(rem, divisor) >= 0 ? 1L : 0L);
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
        // @since 1.8
//        return Long.parseUnsignedLong(s);
        return new java.math.BigInteger(s).longValue();
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

    /** @deprecated Use {@link Nat#xorTo64(int, long[], int, long[], int)} instead. */
    public static void xorTo(int len, long[] x, int xOff, long[] z, int zOff)
    {
        Nat.xorTo64(len, x, xOff, z, zOff);
    }
}
