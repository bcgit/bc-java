package org.bouncycastle.math.raw;

import java.math.BigInteger;

import org.bouncycastle.util.Pack;

public abstract class Nat576
{
    public static void copy64(long[] x, long[] z)
    {
        z[0] = x[0];
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
        z[4] = x[4];
        z[5] = x[5];
        z[6] = x[6];
        z[7] = x[7];
        z[8] = x[8];
    }

    public static void copy64(long[] x, int xOff, long[] z, int zOff)
    {
        z[zOff + 0] = x[xOff + 0];
        z[zOff + 1] = x[xOff + 1];
        z[zOff + 2] = x[xOff + 2];
        z[zOff + 3] = x[xOff + 3];
        z[zOff + 4] = x[xOff + 4];
        z[zOff + 5] = x[xOff + 5];
        z[zOff + 6] = x[xOff + 6];
        z[zOff + 7] = x[xOff + 7];
        z[zOff + 8] = x[xOff + 8];
    }

    public static long[] create64()
    {
        return new long[9];
    }

    public static long[] createExt64()
    {
        return new long[18];
    }

    public static boolean eq64(long[] x, long[] y)
    {
        for (int i = 8; i >= 0; --i)
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
        if (x.signum() < 0 || x.bitLength() > 576)
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
        for (int i = 1; i < 9; ++i)
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
        for (int i = 0; i < 9; ++i)
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
        byte[] bs = new byte[72];
        for (int i = 0; i < 9; ++i)
        {
            long x_i = x[i];
            if (x_i != 0L)
            {
                Pack.longToBigEndian(x_i, bs, (8 - i) << 3);
            }
        }
        return new BigInteger(1, bs);
    }
}
