package org.bouncycastle.util;

/**
 * Utility methods and constants for bytes.
 */
public class Bytes
{
    public static final int BYTES = 1;
    public static final int SIZE = Byte.SIZE;

    public static void xor(int len, byte[] x, byte[] y, byte[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] = (byte)(x[i] ^ y[i]);
        }
    }

    public static void xor(int len, byte[] x, int xOff, byte[] y, int yOff, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff + i] = (byte)(x[xOff + i] ^ y[yOff + i]);
        }
    }

    public static void xorTo(int len, byte[] x, byte[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] ^= x[i];
        }
    }

    public static void xorTo(int len, byte[] x, int xOff, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff + i] ^= x[xOff + i];
        }
    }
}
