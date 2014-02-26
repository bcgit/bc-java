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

    public static void reduce(int[] xx, int[] z)
    {
        long xx06 = xx[6] & M, xx07 = xx[7] & M, xx08 = xx[8] & M;
        long xx09 = xx[9] & M, xx10 = xx[10] & M, xx11 = xx[11] & M;

        long t0 = xx06 + xx10;
        long t1 = xx07 + xx11;

        long cc = 0;
        cc += (xx[0] & M) + t0;
        z[0] = (int)cc;
        cc >>= 32;
        cc += (xx[1] & M) + t1;
        z[1] = (int)cc;
        cc >>= 32;

        t0 += xx08;
        t1 += xx09;

        cc += (xx[2] & M) + t0;
        z[2] = (int)cc;
        cc >>= 32;
        cc += (xx[3] & M) + t1;
        z[3] = (int)cc;
        cc >>= 32;

        t0 -= xx06;
        t1 -= xx07;

        cc += (xx[4] & M) + t0;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (xx[5] & M) + t1;
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

    public static void reduce32(int x, int[] z)
    {
        int c = Nat192.addWord(x, z, 0) + Nat192.addWord(x, z, 2);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
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
