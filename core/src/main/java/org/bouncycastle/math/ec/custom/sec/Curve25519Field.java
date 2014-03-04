package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.Nat;

public class Curve25519Field
{
    // 2^255 - 2^4 - 2^1 - 1
    static final int[] P = new int[]{ 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0x7FFFFFFF };
    private static final int P7 = 0x7FFFFFFF;
    private static final int[] PExt = new int[]{ 0x00000169, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0x3FFFFFFF };
    private static final int PInv = 0x13;

    public static void add(int[] x, int[] y, int[] z)
    {
        Nat256.add(x, y, z);
        if (Nat256.gte(z, P))
        {
            Nat256.addWord(PInv, z, 0);
            z[7] &= P7;
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        Nat256.addExt(xx, yy, zz);
        if (Nat256.gteExt(zz, PExt))
        {
            Nat256.subExt(zz, PExt, zz);
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        Nat256.copy(x, z);
        Nat256.inc(z, 0);
        if (Nat256.gte(z, P))
        {
            Nat256.addWord(PInv, z, 0);
            z[7] &= P7;
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat256.fromBigInteger(x);
        while (Nat256.gte(z, P))
        {
            Nat256.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat.shiftDownBit(8, x, 0, z);
        }
        else
        {
            Nat256.add(x, P, z);
            Nat.shiftDownBit(8, z, 0);
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
//        assert xx[15] >>> 30 == 0;

        int xx07 = xx[7];
        Nat.shiftUpBit(8, xx, 8, xx07, z, 0);
        int c = Nat256.mulByWordAddTo(PInv, xx, z) << 1;
        int z07 = z[7];
        z[7] = z07 & P7;
        c += (z07 >>> 31) - (xx07 >>> 31);
        Nat256.addWord(c * PInv, z, 0);
        if (Nat256.gte(z, P))
        {
            Nat256.addWord(PInv, z, 0);
            z[7] &= P7;
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
            Nat256.subWord(PInv, z, 0);
            z[7] &= P7;
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
        Nat.shiftUpBit(8, x, 0, z);
        if (Nat256.gte(z, P))
        {
            Nat256.addWord(PInv, z, 0);
            z[7] &= P7;
        }
    }
}
