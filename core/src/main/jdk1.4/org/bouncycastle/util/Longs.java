package org.bouncycastle.util;

public class Longs
{
    public static long reverse(long i)
    {
        i = bitPermuteStepSimple(i, 0x5555555555555555L, 1);
        i = bitPermuteStepSimple(i, 0x3333333333333333L, 2);
        i = bitPermuteStepSimple(i, 0x0F0F0F0F0F0F0F0FL, 4);
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
        return (i << distance) ^ (i >>> -distance);
    }

    public static long rotateRight(long i, int distance)
    {
        return (i >>> distance) ^ (i << -distance);
    }

    public static Long valueOf(long value)
    {
        return new Long(value);
    }

    private static long bitPermuteStepSimple(long x, long m, int s)
    {
        return ((x & m) << s) | ((x >>> s) & m);
    }
}
