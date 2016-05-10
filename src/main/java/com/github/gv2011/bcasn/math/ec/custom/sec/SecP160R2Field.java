package com.github.gv2011.bcasn.math.ec.custom.sec;

import java.math.BigInteger;

import com.github.gv2011.bcasn.math.raw.Nat;
import com.github.gv2011.bcasn.math.raw.Nat160;

public class SecP160R2Field
{
    // 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
    static final int[] P = new int[]{ 0xFFFFAC73, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    static final int[] PExt = new int[]{ 0x1B44BBA9, 0x0000A71A, 0x00000001, 0x00000000, 0x00000000,
        0xFFFF58E6, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xE4BB4457, 0xFFFF58E5, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0x0000A719, 0x00000002 };
    private static final int P4 = 0xFFFFFFFF;
    private static final int PExt9 = 0xFFFFFFFF;
    private static final int PInv33 = 0x538D;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat160.add(x, y, z);
        if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
        {
            Nat.add33To(5, PInv33, z);
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
            Nat.add33To(5, PInv33, z);
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
        if (Nat160.isZero(x))
        {
            Nat160.zero(z);
        }
        else
        {
            Nat160.sub(P, x, z);
        }
    }

    public static void reduce(int[] xx, int[] z)
    {
        long cc = Nat160.mul33Add(PInv33, xx, 5, xx, 0, z, 0);
        int c = Nat160.mul33DWordAdd(PInv33, cc, z, 0);

        // assert c == 0 || c == 1;

        if (c != 0 || (z[4] == P4 && Nat160.gte(z, P)))
        {
            Nat.add33To(5, PInv33, z);
        }
    }

    public static void reduce32(int x, int[] z)
    {
        if ((x != 0 && Nat160.mul33WordAdd(PInv33, x, z, 0) != 0)
            || (z[4] == P4 && Nat160.gte(z, P)))
        {
            Nat.add33To(5, PInv33, z);
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
            Nat.sub33From(5, PInv33, z);
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
            Nat.add33To(5, PInv33, z);
        }
    }
}
