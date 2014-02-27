package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

public class SecP224K1Field
{
    // 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1
    static final int[] P = new int[]{ 0xFFFFE56D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF };
    private static final int P6 = 0xFFFFFFFF;
    private static final int[] PExt = new int[]{ 0x02C23069, 0x00003526, 0x00000001, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0xFFFFCADA, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int PExt13 = 0xFFFFFFFF;
    private static final long PInv = 0x0000000100001A93L; 
    private static final int PInv33 = 0x1A93;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat224.add(x, y, z);
        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            Nat224.addDWord(PInv, z, 0);
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
            Nat224.addDWord(PInv, z, 0);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat224.fromBigInteger(x);
        if (z[6] == P6 && Nat224.gte(z, P))
        {
            Nat224.addDWord(PInv, z, 0);
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
        long c = Nat224.mul33Add(PInv33, xx, 7, xx, 0, z, 0);
        c = Nat224.mul33DWordAdd(PInv33, c, z, 0);

        // assert c == 0L || c == 1L;

        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            Nat224.addDWord(PInv, z, 0);
        }
    }

    public static void reduce32(int x, int[] z)
    {
        int c = Nat224.mul33WordAdd(PInv33, x, z, 0);

        // assert c == 0L || c == 1L;

        if (c != 0 || (z[6] == P6 && Nat224.gte(z, P)))
        {
            Nat224.addDWord(PInv, z, 0);
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
            Nat224.subDWord(PInv, z);
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
            Nat224.addDWord(PInv, z, 0);
        }
    }
}
