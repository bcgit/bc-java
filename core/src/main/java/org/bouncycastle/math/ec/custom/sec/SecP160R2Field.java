package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat160;
import org.bouncycastle.util.Pack;

public class SecP160R2Field
{
    // 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1
    static final int[] P = new int[]{ 0xFFFFAC73, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExt = new int[]{ 0x1B44BBA9, 0x0000A71A, 0x00000001, 0x00000000, 0x00000000, 0xFFFF58E6,
        0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
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

    public static void inv(int[] x, int[] z)
    {
        /*
         * Raise this element to the exponent 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 3
         *
         * Breaking up the exponent's binary representation into "repunits", we get:
         * { 127 1s } { 1 0s } { 17 1s } "010110001110001"
         *
         * Therefore we need an addition chain containing 1, 2, 3, 17, 127 (the lengths of the repunits)
         * We use: 1, 2, 3, 6, 12, 15, [17], 34, 68, 102, 119, 125, [127]
         */

        if (0 != isZero(x))
        {
            throw new IllegalArgumentException("'x' cannot be 0");
        }

        int[] x1 = x;
        int[] x2 = Nat160.create();
        square(x1, x2);
        multiply(x2, x1, x2);
        int[] x3 = Nat160.create();
        square(x2, x3);
        multiply(x3, x1, x3);
        int[] x6 = Nat160.create();
        squareN(x3, 3, x6);
        multiply(x6, x3, x6);
        int[] x12 = Nat160.create();
        squareN(x6, 6, x12);
        multiply(x12, x6, x12);
        int[] x15 = x12;
        squareN(x12, 3, x15);
        multiply(x15, x3, x15);
        int[] x17 = x15;
        squareN(x15, 2, x17);
        multiply(x17, x2, x17);
        int[] x34 = Nat160.create();
        squareN(x17, 17, x34);
        multiply(x34, x17, x34);
        int[] x68 = Nat160.create();
        squareN(x34, 34, x68);
        multiply(x68, x34, x68);
        int[] x102 = x68;
        squareN(x68, 34, x102);
        multiply(x102, x34, x102);
        int[] x119 = x34;
        squareN(x102, 17, x119);
        multiply(x119, x17, x119);
        int[] x125 = x102;
        squareN(x119, 6, x125);
        multiply(x125, x6, x125);
        int[] x127 = x6;
        squareN(x125, 2, x127);
        multiply(x127, x2, x127);

        int[] t = x127;
        squareN(t, 18, t);
        multiply(t, x17, t);
        squareN(t, 2, t);
        multiply(t, x1, t);
        squareN(t, 3, t);
        multiply(t, x2, t);
        squareN(t, 6, t);
        multiply(t, x3, t);
        squareN(t, 4, t);

        // NOTE that x1 and z could be the same array
        multiply(x1, t, z);
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
