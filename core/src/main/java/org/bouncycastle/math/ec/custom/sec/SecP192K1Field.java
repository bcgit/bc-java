package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.Pack;

public class SecP192K1Field
{
    // 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1
    static final int[] P = new int[]{ 0xFFFFEE37, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExt = new int[]{ 0x013C4FD1, 0x00002392, 0x00000001, 0x00000000, 0x00000000, 0x00000000,
        0xFFFFDC6E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xFEC3B02F, 0xFFFFDC6D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0x00002391, 0x00000002 };
    private static final int P5 = 0xFFFFFFFF;
    private static final int PExt11 = 0xFFFFFFFF;
    private static final int PInv33 = 0x11C9;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat192.add(x, y, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat.add33To(6, PInv33, z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.add(12, xx, yy, zz);
        if (c != 0 || (zz[11] == PExt11 && Nat.gte(12, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(12, zz, PExtInv.length);
            }
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(6, x, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat.add33To(6, PInv33, z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat192.fromBigInteger(x);
        if (z[5] == P5 && Nat192.gte(z, P))
        {
            Nat192.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat.shiftDownBit(6, x, 0, z);
        }
        else
        {
            int c = Nat192.add(x, P, z);
            Nat.shiftDownBit(6, z, c);
        }
    }

    public static void inv(int[] x, int[] z)
    {
        /*
         * Raise this element to the exponent 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 3
         *
         * Breaking up the exponent's binary representation into "repunits", we get:
         * { 159 1s } { 1 0s } { 19 1s } { 1 0s } { 3 1s } "000110101"
         *
         * Therefore we need an addition chain containing 1, 2, 3, 19, 159 (the lengths of the repunits)
         * We use: [1], [2], [3], 6, 12, 18, [19], 38, 76, 152, 158, [159]
         */

        if (0 != isZero(x))
        {
            throw new IllegalArgumentException("'x' cannot be 0");
        }

        int[] x1 = x;
        int[] x2 = Nat192.create();
        square(x1, x2);
        multiply(x2, x1, x2);
        int[] x3 = Nat192.create();
        square(x2, x3);
        multiply(x3, x1, x3);
        int[] x6 = Nat192.create();
        squareN(x3, 3, x6);
        multiply(x6, x3, x6);
        int[] x12 = Nat192.create();
        squareN(x6, 6, x12);
        multiply(x12, x6, x12);
        int[] x18 = x12;
        squareN(x12, 6, x18);
        multiply(x18, x6, x18);
        int[] x19 = x18;
        square(x18, x19);
        multiply(x19, x1, x19);
        int[] x38 = Nat192.create();
        squareN(x19, 19, x38);
        multiply(x38, x19, x38);
        int[] x76 = Nat192.create();
        squareN(x38, 38, x76);
        multiply(x76, x38, x76);
        int[] x152 = x38;
        squareN(x76, 76, x152);
        multiply(x152, x76, x152);
        int[] x158 = x76;
        squareN(x152, 6, x158);
        multiply(x158, x6, x158);
        int[] x159 = x6;
        square(x158, x159);
        multiply(x159, x1, x159);

        int[] t = x159;
        squareN(t, 20, t);
        multiply(t, x19, t);
        squareN(t, 4, t);
        multiply(t, x3, t);
        squareN(t, 5, t);
        multiply(t, x2, t);
        squareN(t, 2, t);
        multiply(t, x1, t);
        squareN(t, 2, t);

        // NOTE that x1 and z could be the same array
        multiply(x1, t, z);
    }

    public static int isZero(int[] x)
    {
        int d = 0;
        for (int i = 0; i < 6; ++i)
        {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat192.createExt();
        Nat192.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz)
    {
        int c = Nat192.mulAddTo(x, y, zz);
        if (c != 0 || (zz[11] == PExt11 && Nat.gte(12, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(12, zz, PExtInv.length);
            }
        }
    }

    public static void negate(int[] x, int[] z)
    {
        if (0 != isZero(x))
        {
            Nat192.sub(P, P, z);
        }
        else
        {
            Nat192.sub(P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z)
    {
        byte[] bb = new byte[6 * 4];
        do
        {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 6);
        }
        while (0 == Nat.lessThan(6, z, P));
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
        long cc = Nat192.mul33Add(PInv33, xx, 6, xx, 0, z, 0);
        int c = Nat192.mul33DWordAdd(PInv33, cc, z, 0);

        // assert c == 0L || c == 1L;

        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat.add33To(6, PInv33, z);
        }
    }

    public static void reduce32(int x, int[] z)
    {
        if ((x != 0 && Nat192.mul33WordAdd(PInv33, x, z, 0) != 0)
            || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat.add33To(6, PInv33, z);
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
            Nat.sub33From(6, PInv33, z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.sub(12, xx, yy, zz);
        if (c != 0)
        {
            if (Nat.subFrom(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.decAt(12, zz, PExtInv.length);
            }
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(6, x, 0, z);
        if (c != 0 || (z[5] == P5 && Nat192.gte(z, P)))
        {
            Nat.add33To(6, PInv33, z);
        }
    }
}
