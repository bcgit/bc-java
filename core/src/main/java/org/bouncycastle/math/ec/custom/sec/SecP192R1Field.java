package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

public class SecP192R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^192 - 2^64 - 1
    static final int[] P = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int P5 = 0xFFFFFFFF;
    private static final int[] PExt = new int[]{ 0x00000001, 0x00000000, 0x00000002, 0x00000000, 0x00000001,
        0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int PExt11 = 0xFFFFFFFF;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat192.add(x, y, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat192.sub(z, P, z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat192.addExt(xx, yy, zz);
        if (c != 0 || (zz[11] == PExt11 && Nat192.gteExt(zz, PExt)))
        {
            Nat192.subExt(zz, PExt, zz);
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        System.arraycopy(x, 0, z, 0, 6);
        int c = Nat192.inc(z, 0);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat192.sub(z, P, z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat192.fromBigInteger(x);
        if (z[5] == P5 && Nat192.gte(z, P))
        {
            Nat192.sub(z, P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat192.shiftDownBit(x, 0, z);
        }
        else
        {
            int c = Nat192.add(x, P, z);
            Nat192.shiftDownBit(z, c, z);
        }
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat192.createExt();
        Nat192.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat192.isZero(x))
        {
            Nat192.zero(z);
        }
        else
        {
            Nat192.sub(P, x, z);
        }
    }

    public static void reduce(int[] tt, int[] z)
    {
        long t06 = tt[6] & M, t07 = tt[7] & M, t08 = tt[8] & M;
        long t09 = tt[9] & M, t10 = tt[10] & M, t11 = tt[11] & M;

        long cc = 0;
        cc += (tt[0] & M) + t06 + t10;
        z[0] = (int)cc;
        cc >>= 32;
        cc += (tt[1] & M) + t07 + t11;
        z[1] = (int)cc;
        cc >>= 32;
        cc += (tt[2] & M) + t06 + t08 + t10;
        z[2] = (int)cc;
        cc >>= 32;
        cc += (tt[3] & M) + t07 + t09 + t11;
        z[3] = (int)cc;
        cc >>= 32;
        cc += (tt[4] & M) + t08 + t10;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (tt[5] & M) + t09 + t11;
        z[5] = (int)cc;
        cc >>= 32;

        int c = (int)cc;
        while (c > 0)
        {
            c += Nat192.sub(z, P, z);
        }

        if (z[5] == P5 && Nat192.gte(z, P))
        {
            Nat192.sub(z, P, z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat192.createExt();
        Nat192.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat192.createExt();
        Nat192.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat192.square(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat192.sub(x, y, z);
        if (c != 0)
        {
            Nat192.add(z, P, z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat192.subExt(xx, yy, zz);
        if (c != 0)
        {
            Nat192.addExt(zz, PExt, zz);
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat192.shiftUpBit(x, 0, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat192.sub(z, P, z);
        }
    }
}
