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

    public static Integer valueOf(int value)
    {
        return Integer.valueOf(value);
    }
}
