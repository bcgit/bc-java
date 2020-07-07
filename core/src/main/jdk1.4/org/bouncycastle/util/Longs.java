package org.bouncycastle.util;

public class Longs
{
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
}
