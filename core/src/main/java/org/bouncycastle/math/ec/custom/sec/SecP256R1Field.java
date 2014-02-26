package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

public class SecP256R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^256 - 2^224 + 2^192 + 2^96 - 1
    static final int[] P = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000,
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

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat256.shiftDownBit(x, 0, z);
        }
        else
        {
            int c = Nat256.add(x, P, z);
            Nat256.shiftDownBit(z, c, z);
        }
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

    public static void reduce(int[] xx, int[] z)
    {
        long xx08 = xx[8] & M, xx09 = xx[9] & M, xx10 = xx[10] & M, xx11 = xx[11] & M;
        long xx12 = xx[12] & M, xx13 = xx[13] & M, xx14 = xx[14] & M, xx15 = xx[15] & M;

        long t0 = xx08 + xx09;
        long t1 = xx09 + xx10;
        long t2 = xx10 + xx11;
        long t3 = xx11 + xx12;
        long t4 = xx12 + xx13;
        long t5 = xx13 + xx14;
        long t6 = xx14 + xx15;

        long cc = 0;
        cc += (xx[0] & M) + t0 - t3 - t5;
        z[0] = (int)cc;
        cc >>= 32;
        cc += (xx[1] & M) + t1 - t4 - t6;
        z[1] = (int)cc;
        cc >>= 32;
        cc += (xx[2] & M) + t2 - t5 - xx15;
        z[2] = (int)cc;
        cc >>= 32;
        cc += (xx[3] & M) + (t3 << 1) + xx13 - xx15 - t0;
        z[3] = (int)cc;
        cc >>= 32;
        cc += (xx[4] & M) + (t4 << 1) + xx14 - t1;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (xx[5] & M) + (t5 << 1) + xx15 - t2;
        z[5] = (int)cc;
        cc >>= 32;
        cc += (xx[6] & M) + (t6 << 1) + t5 - t0;
        z[6] = (int)cc;
        cc >>= 32;
        cc += (xx[7] & M) + (xx15 << 1) + xx15 + xx08 - t2 - t4;
        z[7] = (int)cc;
        cc >>= 32;

        int c = (int)cc;
        if (c < 0)
        {
            do
            {
                c += Nat256.add(z, P, z);
            }
            while (c < 0);
        }
        else
        {
            while (c > 0)
            {
                c += Nat256.sub(z, P, z);
            }

            if (z[7] == P7 && Nat256.gte(z, P))
            {
                Nat256.sub(z, P, z);
            }
        }
    }

    public static void reduce32(int x, int[] z)
    {
        long xx08 = x & M;

        long cc = 0;
        cc += (z[0] & M) + xx08;
        z[0] = (int)cc;
        cc >>= 32;
        cc += (z[1] & M);
        z[1] = (int)cc;
        cc >>= 32;
        cc += (z[2] & M);
        z[2] = (int)cc;
        cc >>= 32;
        cc += (z[3] & M) - xx08;
        z[3] = (int)cc;
        cc >>= 32;
        cc += (z[4] & M);
        z[4] = (int)cc;
        cc >>= 32;
        cc += (z[5] & M);
        z[5] = (int)cc;
        cc >>= 32;
        cc += (z[6] & M) - xx08;
        z[6] = (int)cc;
        cc >>= 32;
        cc += (z[7] & M) + xx08;
        z[7] = (int)cc;
        cc >>= 32;

        if (cc != 0 || (z[7] == P7 && Nat256.gte(z, P)))
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

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat256.createExt();
        Nat256.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat256.square(z, tt);
            reduce(tt, z);
        }
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

    public static void twice(int[] x, int[] z)
    {
        int c = Nat256.shiftUpBit(x, 0, z);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat256.sub(z, P, z);
        }
    }
}
