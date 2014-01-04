package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

public class SecP256R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^256 - 2^224 + 2^192 + 2^96 - 1
    private static final int[] P = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000,
        0x00000001, 0xFFFFFFFF };
    private static final int P7 = 0xFFFFFFFF;
    private static final int[] PExt = new int[]{ 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0xFFFFFFFE, 0x00000001, 0x00000001, 0xFFFFFFFE,
        0x00000002, 0xFFFFFFFE };

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat256.add(x, y, z);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat256.sub(z, P, z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat256.addExt(xx, yy, zz);
        if (c != 0 || Nat256.gteExt(zz, PExt))
        {
            Nat256.subExt(zz, PExt, zz);
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        System.arraycopy(x, 0, z, 0, 8);
        int c = Nat256.inc(z, 0);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat256.sub(z, P, z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat256.fromBigInteger(x);
        if (z[7] == P7 && Nat256.gte(z, P))
        {
            Nat256.sub(z, P, z);
        }
        return z;
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat256.createExt();
        Nat256.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat256.isZero(x))
        {
            Nat256.zero(z);
        }
        else
        {
            Nat256.sub(P, x, z);
        }
    }

    public static void reduce(int[] tt, int[] z)
    {
        long t08 = tt[8] & M, t09 = tt[9] & M, t10 = tt[10] & M, t11 = tt[11] & M;
        long t12 = tt[12] & M, t13 = tt[13] & M, t14 = tt[14] & M, t15 = tt[15] & M;

        long cc = 0;
        cc += (tt[0] & M) + t08 + t09 - t11 - t12 - t13 - t14;
        z[0] = (int)cc;
        cc >>= 32;
        cc += (tt[1] & M) + t09 + t10 - t12 - t13 - t14 - t15;
        z[1] = (int)cc;
        cc >>= 32;
        cc += (tt[2] & M) + t10 + t11 - t13 - t14 - t15;
        z[2] = (int)cc;
        cc >>= 32;
        cc += (tt[3] & M) + ((t11 + t12) << 1) + t13 - t15 - t08 - t09;
        z[3] = (int)cc;
        cc >>= 32;
        cc += (tt[4] & M) + ((t12 + t13) << 1) + t14 - t09 - t10;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (tt[5] & M) + ((t13 + t14) << 1) + t15 - t10 - t11;
        z[5] = (int)cc;
        cc >>= 32;
        cc += (tt[6] & M) + ((t14 + t15) << 1) + t14 + t13 - t08 - t09;
        z[6] = (int)cc;
        cc >>= 32;
        cc += (tt[7] & M) + (t15 << 1) + t15 + t08 - t10 - t11 - t12 - t13;
        z[7] = (int)cc;
        cc >>= 32;

        int c = (int)cc;

        if (c > 0)
        {
            do
            {
                c += Nat256.sub(z, P, z);
            }
            while (c != 0);
        }
        else if (c < 0)
        {
            do
            {
                c += Nat256.add(z, P, z);
            }
            while (c != 0);
        }

        // assert c == 0;

        if (z[7] == P7 && Nat256.gte(z, P))
        {
            Nat256.sub(z, P, z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat256.createExt();
        Nat256.square(x, tt);
        reduce(tt, z);
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat256.sub(x, y, z);
        if (c != 0)
        {
            Nat256.add(z, P, z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat256.subExt(xx, yy, zz);
        if (c != 0)
        {
            Nat256.addExt(zz, PExt, zz);
        }
    }
}
