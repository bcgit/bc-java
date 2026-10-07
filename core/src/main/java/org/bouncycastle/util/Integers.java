package org.bouncycastle.util;

/**
 * Utility methods and constants for ints.
 */
public class Integers
{
    public static final int BYTES = 4;
    public static final int SIZE = Integer.SIZE;

    public static int bitCount(int i)
    {
        return Integer.bitCount(i);
    }

    public static int bitLength(int i)
    {
        return SIZE - numberOfLeadingZeros(i);
    }

    public static int compare(int x, int y)
    {
        // @since 1.7
//        return Integer.compare(x, y);
        return x < y ? -1 : x == y ? 0 : 1;
    }

    public static int compareUnsigned(int x, int y)
    {
        // @since 1.8
//        return Integer.compareUnsigned(x, y);
        return compare(x + Integer.MIN_VALUE, y + Integer.MIN_VALUE);
    }

    public static int highestOneBit(int i)
    {
        return Integer.highestOneBit(i);
    }

    public static int lowestOneBit(int i)
    {
        return Integer.lowestOneBit(i);
    }

    public static int numberOfLeadingZeros(int i)
    {
        return Integer.numberOfLeadingZeros(i);
    }

    public static int numberOfTrailingZeros(int i)
    {
        return Integer.numberOfTrailingZeros(i);
    }

    public static int reverse(int i)
    {
        return Integer.reverse(i);
    }

    public static int reverseBytes(int i)
    {
        return Integer.reverseBytes(i);
    }

    public static int rotateLeft(int i, int distance)
    {
        return Integer.rotateLeft(i, distance);
    }

    public static int rotateRight(int i, int distance)
    {
        return Integer.rotateRight(i, distance);
    }

    /**
     * Return the big-endian encoding of {@code i} taken as an unsigned 32-bit value, in the fewest
     * octets that hold its significant bits: 0 is the empty array, 255 is {@code FF}, 256 is
     * {@code 01 00}, and a negative argument takes all four.
     */
    public static byte[] toUnsignedByteArray(int i)
    {
        int len = (bitLength(i) + 7) >>> 3;
        byte[] bs = new byte[len];
        for (int pos = len - 1; pos >= 0; --pos)
        {
            bs[pos] = (byte)i;
            i >>>= 8;
        }
        return bs;
    }

    public static Integer valueOf(int value)
    {
        return Integer.valueOf(value);
    }
}
