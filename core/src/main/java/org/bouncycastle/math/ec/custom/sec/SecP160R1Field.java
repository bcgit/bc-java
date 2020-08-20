package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat160;
import org.bouncycastle.util.Pack;

public class SecP160R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^160 - 2^31 - 1
    static final int[] P = new int[]{ 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExt = new int[]{ 0x00000001, 0x40000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE,
        0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xFFFFFFFF, 0xBFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0x00000001, 0x00000001 };
    private static final int P4 = 0xFFFFFFFF;
    private static final int PExt9 = 0xFFFFFFFF;
    private static final int PInv = 0x80000001;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat160.add(x, y, z);
        if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
        {
            Nat.addWordTo(5, PInv, z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.add(10, xx, yy, zz);
        if (c != 0 || (zz[9] == PExt9 && Nat.gte(10, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(10, zz, PExtInv.length);
            }
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(5, x, z);
        if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
        {
            Nat.addWordTo(5, PInv, z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat160.fromBigInteger(x);
        if (z[4] == P4 && Nat160.gte(z, P))
        {
            Nat160.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat.shiftDownBit(5, x, 0, z);
        }
        else
        {
            int c = Nat160.add(x, P, z);
            Nat.shiftDownBit(5, z, c);
        }
    }

    public static void inv(int[] x, int[] z)
    {
        Mod.checkedModOddInverse(P, x, z);
    }

    public static int isZero(int[] x)
    {
        int d = 0;
        for (int i = 0; i < 5; ++i)
        {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat160.createExt();
        Nat160.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz)
    {
        int c = Nat160.mulAddTo(x, y, zz);
        if (c != 0 || (zz[9] == PExt9 && Nat.gte(10, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(10, zz, PExtInv.length);
            }
        }
    }

    public static void negate(int[] x, int[] z)
    {
        if (0 != isZero(x))
        {
            Nat160.sub(P, P, z);
        }
        else
        {
            Nat160.sub(P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z)
    {
        byte[] bb = new byte[5 * 4];
        do
        {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 5);
        }
        while (0 == Nat.lessThan(5, z, P));
    }

    public static void randomMult(SecureRandom r, int[] z)
    {
        do
        {
            random(r, z);
        }
        while (0 != isZero(z));
    }

    public static void reduce(int[] xx, int[] z)
    {
        long x5 = xx[5] & M, x6 = xx[6] & M, x7 = xx[7] & M, x8 = xx[8] & M, x9 = xx[9] & M;

        long c = 0;
        c += (xx[0] & M) + x5 + (x5 << 31);
        z[0] = (int)c; c >>>= 32;
        c += (xx[1] & M) + x6 + (x6 << 31);
        z[1] = (int)c; c >>>= 32;
        c += (xx[2] & M) + x7 + (x7 << 31);
        z[2] = (int)c; c >>>= 32;
        c += (xx[3] & M) + x8 + (x8 << 31);
        z[3] = (int)c; c >>>= 32;
        c += (xx[4] & M) + x9 + (x9 << 31);
        z[4] = (int)c; c >>>= 32;

//        assert c >>> 32 == 0;

        reduce32((int)c, z);
    }

    public static void reduce32(int x, int[] z)
    {
        if ((x != 0 && Nat160.mulWordsAdd(PInv, x, z, 0) != 0)
            || (z[4] == P4 && Nat160.gte(z, P)))
        {
            Nat.addWordTo(5, PInv, z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat160.createExt();
        Nat160.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat160.createExt();
        Nat160.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat160.square(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat160.sub(x, y, z);
        if (c != 0)
        {
            Nat.subWordFrom(5, PInv, z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.sub(10, xx, yy, zz);
        if (c != 0)
        {
            if (Nat.subFrom(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.decAt(10, zz, PExtInv.length);
            }
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(5, x, 0, z);
        if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
        {
            Nat.addWordTo(5, PInv, z);
        }
    }
}
