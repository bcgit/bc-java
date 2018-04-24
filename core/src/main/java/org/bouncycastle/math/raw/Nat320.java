package org.bouncycastle.math.raw;

import java.math.BigInteger;

import org.bouncycastle.util.Pack;

public abstract class Nat320
{
    public static void copy64(long[] x, long[] z)
    {
        z[0] = x[0];
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
        z[4] = x[4];
    }

    public static void copy64(long[] x, int xOff, long[] z, int zOff)
    {
        z[zOff + 0] = x[xOff + 0];
        z[zOff + 1] = x[xOff + 1];
        z[zOff + 2] = x[xOff + 2];
        z[zOff + 3] = x[xOff + 3];
        z[zOff + 4] = x[xOff + 4];
    }

    public static long[] create64()
    {
        return new long[5];
    }

    public static long[] createExt64()
    {
        return new long[10];
    }

    public static boolean eq64(long[] x, long[] y)
    {
        for (int i = 4; i >= 0; --i)
        {
            if (x[i] != y[i])
            {
                return false;
            }
        }
        return true;
    }

    public static long[] fromBigInteger64(BigInteger x)
    {
        if (x.signum() < 0 || x.bitLength() > 320)
        {
            throw new IllegalArgumentException();
        }

        long[] z = create64();
        int i = 0;
        while (x.signum() != 0)
        {
            z[i++] = x.longValue();
            x = x.shiftRight(64);
        }
        return z;
    }

    public static boolean isOne64(long[] x)
    {
        if (x[0] != 1L)
        {
            return false;
        }
        for (int i = 1; i < 5; ++i)
        {
            if (x[i] != 0L)
            {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero64(long[] x)
    {
        for (int i = 0; i < 5; ++i)
        {
            if (x[i] != 0L)
            {
                return false;
            }
        }
        return true;
    }

    public static BigInteger toBigInteger64(long[] x)
    {
        byte[] bs = new byte[40];
        for (int i = 0; i < 5; ++i)
        {
            long x_i = x[i];
            if (x_i != 0L)
            {
                Pack.longToBigEndian(x_i, bs, (4 - i) << 3);
            }
        }
        return new BigInteger(1, bs);
    }
}
