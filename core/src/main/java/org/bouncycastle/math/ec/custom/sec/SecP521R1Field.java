package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.Nat;

public class SecP521R1Field
{
    // 2^521 - 1
    static final int[] P = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x1FF };
    private static final int P16 = 0x1FF;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat.add(16, x, y, z) + x[16] + y[16];
        if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
        {
            c += Nat.inc(16, z, 0);
            c &= P16;
        }
        z[16] = c;
    }

    public static void addOne(int[] x, int[] z)
    {
        System.arraycopy(x, 0, z, 0, 16);
        int c = Nat.inc(16, z, 0) + z[16];
        if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
        {
            c += Nat.inc(16, z, 0);
            c &= P16;
        }
        z[16] = c;
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat.fromBigInteger(521, x);
        if (Nat.eq(17, z, P))
        {
            Nat.zero(17, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        int c0 = x[0] & 1, x16 = x[16], c512 = x16 & 1;
        Nat.shiftDownBit(16, x, c512, z);
        z[16] = (x16 >>> 1) | (c0 << 8);
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat.create(34);
        Nat.mul(17, x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z)
    {
        if (Nat.isZero(17, x))
        {
            Nat.zero(17, z);
        }
        else
        {
            Nat.sub(17, P, x, z);
        }
    }

    public static void reduce(int[] xx, int[] z)
    {
//        assert xx[33] == 0;
//        assert xx[32] >>> 18 == 0;

        int xx32 = xx[32];
        int c = Nat.shiftDownBitsExt(16, xx, 16, 9, xx32, z) >>> 23;
        c += xx32 >>> 9;
        c += Nat.add(16, z, xx, z);
        if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
        {
            c += Nat.inc(16, z, 0);
            c &= P16;
        }
        z[16] = c;
    }

    public static void reduce23(int[] z)
    {
        int z16 = z[16];
        int c = Nat.addWord(16, z16 >>> 9, z) + (z16 & P16);
        if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
        {
            c += Nat.inc(16, z, 0);
            c &= P16;
        }
        z[16] = c;
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat.create(34);
        Nat.square(17, x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat.create(34);
        Nat.square(17, x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat.square(17, z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat.sub(16, x, y, z) + x[16] - y[16];
        if (c < 0)
        {
            c += Nat.dec(16, z, 0);
            c &= P16;
        }
        z[16] = c;
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(16, x, 0, z) | (x[16] << 1);
        if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
        {
            c += Nat.inc(16, z, 0);
            c &= P16;
        }
        z[16] = c;
    }
}
