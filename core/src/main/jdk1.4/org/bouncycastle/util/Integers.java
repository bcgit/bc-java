package org.bouncycastle.util;

public class Integers
{
    public static int numberOfLeadingZeros(int i)
    {
        if (i <= 0)
        {
            return (~i >>> (31 - 5)) & (1 << 5);
        }

        int n = 1;
        if (0 == (i >>> 16)) { n += 16; i <<= 16; }
        if (0 == (i >>> 24)) { n +=  8; i <<=  8; }
        if (0 == (i >>> 28)) { n +=  4; i <<=  4; }
        if (0 == (i >>> 30)) { n +=  2; i <<=  2; }
        n -= (i >>> 31);
        return n;
    }

    public static int rotateLeft(int i, int distance)
    {
        return (i << distance) ^ (i >>> -distance);
    }

    public static int rotateRight(int i, int distance)
    {
        return (i >>> distance) ^ (i << -distance);
    }

    public static Integer valueOf(int value)
    {
        return new Integer(value);
    }
}
