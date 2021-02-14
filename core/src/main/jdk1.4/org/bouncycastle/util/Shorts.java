package org.bouncycastle.util;

/**
 * Utility methods and constants for shorts.
 */
public class Shorts
{
    public static final int BYTES = 2;
    public static final int SIZE = 16;

    public static Short valueOf(short value)
    {
        return new Short(value);
    }
}
