package org.bouncycastle.util;

import org.bouncycastle.math.raw.Nat;

/**
 * Utility methods and constants for bytes.
 */
public class Bytes
{
    public static final int BYTES = 1;
    public static final int SIZE = 8;

    public static void cmov(int len, int cond, byte[] x, byte[] z)
    {
        int m0 = Nat.czero(cond), m1 = ~m0;
        for (int i = 0; i < len; ++i)
        {
            int x_i = x[i], z_i = z[i];
            z[i] = (byte)((z_i & m0) | (x_i & m1));
        }
    }

    public static void cmov(int len, int cond, byte[] x, int xOff, byte[] z, int zOff)
    {
        int m0 = Nat.czero(cond), m1 = ~m0;
        for (int i = 0; i < len; ++i)
        {
            int x_i = x[xOff + i], z_i = z[zOff + i];
            z[zOff + i] = (byte)((z_i & m0) | (x_i & m1));
        }
    }

    public static void xor(int len, byte[] x, byte[] y, byte[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] = (byte)(x[i] ^ y[i]);
        }
    }

    public static void xor(int len, byte[] x, int xOff, byte[] y, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff++] = (byte)(x[xOff++] ^ y[i]);
        }
    }

    public static void xor(int len, byte[] x, int xOff, byte[] y, int yOff, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff + i] = (byte)(x[xOff + i] ^ y[yOff + i]);
        }
    }

    public static void xor(int len, byte[] x, byte[] y, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff++] = (byte)(x[i] ^ y[i]);
        }
    }

    public static void xor(int len, byte[] x, byte[] y, int yOff, byte[] z, int zOff)
    {
        for (int i = 0; i < len; ++i)
        {
            z[zOff++] = (byte)(x[i] ^ y[yOff++]);
        }
    }

    public static void xorTo(int len, byte[] x, byte[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] ^= x[i];
        }
    }

    public static void xorTo(int len, byte[] x, int xOff, byte[] z)
    {
        for (int i = 0; i < len; ++i)
        {
            z[i] ^= x[xOff++];
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
