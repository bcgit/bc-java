package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

public class SecP224R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^224 - 2^96 + 1
    static final int[] P = new int[]{ 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    static final int[] PExt = new int[]{ 0x00000001, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF,
        0xFFFFFFFF, 0x00000000, 0x00000002, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int P6 = 0xFFFFFFFF;
    private static final int PExt13 = 0xFFFFFFFF;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat224.add(x, y, z);
        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            Nat224.sub(z, P, z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat224.addExt(xx, yy, zz);
        if (c != 0 || (zz[13] == PExt13 && Nat224.gteExt(zz, PExt)))
        {
            Nat224.subExt(zz, PExt, zz);
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        Nat224.copy(x, z);
        int c = Nat224.inc(z, 0);
        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            Nat224.sub(z, P, z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat224.fromBigInteger(x);
        if (z[6] == P6 && Nat224.gte(z, P))
        {
            Nat224.sub(z, P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat224.shiftDownBit(x, 0, z);
        }
        else
        {
            int c = Nat224.add(x, P, z);
            Nat224.shiftDownBit(z, c, z);
        }
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat224.createExt();
        Nat224.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat224.isZero(x))
        {
            Nat224.zero(z);
        }
        else
        {
            Nat224.sub(P, x, z);
        }
    }

    public static void reduce(int[] xx, int[] z)
    {
        long xx07 = xx[7] & M, xx08 = xx[8] & M, xx09 = xx[9] & M, xx10 = xx[10] & M;
        long xx11 = xx[11] & M, xx12 = xx[12] & M, xx13 = xx[13] & M;

        long t0 = xx07 + xx11;
        long t1 = xx08 + xx12;
        long t2 = xx09 + xx13;

        long cc = 0;
        cc += (xx[0] & M) - t0;
        z[0] = (int)cc;
        cc >>= 32;
        cc += (xx[1] & M) - t1;
        z[1] = (int)cc;
        cc >>= 32;
        cc += (xx[2] & M) - t2;
        z[2] = (int)cc;
        cc >>= 32;
        cc += (xx[3] & M) + t0 - xx10;
        z[3] = (int)cc;
        cc >>= 32;
        cc += (xx[4] & M) + t1 - xx11;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (xx[5] & M) + t2 - xx12;
        z[5] = (int)cc;
        cc >>= 32;
        cc += (xx[6] & M) + xx10 - xx13;
        z[6] = (int)cc;
        cc >>= 32;

        int c = (int)cc;
        if (c >= 0)
        {
            reduce32(c, z);
        }
        else
        {
            while (c < 0)
            {
                c += Nat224.add(z, P, z);
            }
        }
    }

    public static void reduce32(int x, int[] z)
    {
        if ((x != 0 && (Nat224.subWord(x, z, 0) + Nat224.addWord(x, z, 3) != 0))
            || (z[6] == P6 && Nat224.gte(z, P)))
        {
            Nat224.sub(z, P, z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat224.createExt();
        Nat224.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat224.createExt();
        Nat224.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat224.square(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat224.sub(x, y, z);
        if (c != 0)
        {
            Nat224.add(z, P, z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat224.subExt(xx, yy, zz);
        if (c != 0)
        {
            Nat224.addExt(zz, PExt, zz);
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat224.shiftUpBit(x, 0, z);
        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            Nat224.sub(z, P, z);
        }
    }
}
