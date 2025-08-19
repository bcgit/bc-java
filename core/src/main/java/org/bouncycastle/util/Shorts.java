package org.bouncycastle.util;

/**
 * Utility methods and constants for shorts.
 */
public class Shorts
{
    public static final int BYTES = 2;
    public static final int SIZE = Short.SIZE;

    public static Short valueOf(short value)
    {
        return Short.valueOf(value);
    }

    public static void xorTo(int len, short[] x, short[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] ^= x[i];
        }
    }
}
