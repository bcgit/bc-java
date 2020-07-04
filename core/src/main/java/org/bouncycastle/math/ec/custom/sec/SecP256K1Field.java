package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Pack;

public class SecP256K1Field
{
    // 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    static final int[] P = new int[]{ 0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF };
    static final int[] PExt = new int[]{ 0x000E90A1, 0x000007A2, 0x00000001, 0x00000000, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0xFFFFF85E, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xFFF16F5F, 0xFFFFF85D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x000007A1, 0x00000002 };
    private static final int P7 = 0xFFFFFFFF;
    private static final int PExt15 = 0xFFFFFFFF;
    private static final int PInv33 = 0x3D1;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat256.add(x, y, z);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat.add33To(8, PInv33, z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.add(16, xx, yy, zz);
        if (c != 0 || (zz[15] == PExt15 && Nat.gte(16, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(16, zz, PExtInv.length);
            }
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(8, x, z);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat.add33To(8, PInv33, z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat256.fromBigInteger(x);
        if (z[7] == P7 && Nat256.gte(z, P))
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
            int c = Nat256.add(x, P, z);
            Nat.shiftDownBit(8, z, c);
        }
    }

    public static void inv(int[] x, int[] z)
    {
        /*
         * Raise this element to the exponent 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 3
         *
         * Breaking up the exponent's binary representation into "repunits", we get:
         * { 223 1s } { 1 0s } { 22 1s } { 4 0s } { 1 1s } { 1 0s } { 2 1s } { 1 0s } { 1 1s }
         *
         * Therefore we need an addition chain containing 1, 2, 22, 223 (the lengths of the repunits)
         * We use: [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
         */

        if (0 != isZero(x))
        {
            throw new IllegalArgumentException("'x' cannot be 0");
        }

        int[] x1 = x;
        int[] x2 = Nat256.create();
        square(x1, x2);
        multiply(x2, x1, x2);
        int[] x3 = Nat256.create();
        square(x2, x3);
        multiply(x3, x1, x3);
        int[] x6 = Nat256.create();
        squareN(x3, 3, x6);
        multiply(x6, x3, x6);
        int[] x9 = x6;
        squareN(x6, 3, x9);
        multiply(x9, x3, x9);
        int[] x11 = x9;
        squareN(x9, 2, x11);
        multiply(x11, x2, x11);
        int[] x22 = Nat256.create();
        squareN(x11, 11, x22);
        multiply(x22, x11, x22);
        int[] x44 = x11;
        squareN(x22, 22, x44);
        multiply(x44, x22, x44);
        int[] x88 = Nat256.create();
        squareN(x44, 44, x88);
        multiply(x88, x44, x88);
        int[] x176 = Nat256.create();
        squareN(x88, 88, x176);
        multiply(x176, x88, x176);
        int[] x220 = x88;
        squareN(x176, 44, x220);
        multiply(x220, x44, x220);
        int[] x223 = x44;
        squareN(x220, 3, x223);
        multiply(x223, x3, x223);

        int[] t = x223;
        squareN(t, 23, t);
        multiply(t, x22, t);
        squareN(t, 5, t);
        multiply(t, x1, t);
        squareN(t, 3, t);
        multiply(t, x2, t);
        squareN(t, 2, t);

        // NOTE that x1 and z could be the same array
        multiply(x1, t, z);
    }

    public static int isZero(int[] x)
    {
        int d = 0;
        for (int i = 0; i < 8; ++i)
        {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat256.createExt();
        Nat256.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz)
    {
        int c = Nat256.mulAddTo(x, y, zz);
        if (c != 0 || (zz[15] == PExt15 && Nat.gte(16, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(16, zz, PExtInv.length);
            }
        }
    }

    public static void negate(int[] x, int[] z)
    {
        if (0 != isZero(x))
        {
            Nat256.sub(P, P, z);
        }
        else
        {
            Nat256.sub(P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z)
    {
        byte[] bb = new byte[8 * 4];
        do
        {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 8);
        }
        while (0 == Nat.lessThan(8, z, P));
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
        long cc = Nat256.mul33Add(PInv33, xx, 8, xx, 0, z, 0);
        int c = Nat256.mul33DWordAdd(PInv33, cc, z, 0);

        // assert c == 0L || c == 1L;

        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat.add33To(8, PInv33, z);
        }
    }

    public static void reduce32(int x, int[] z)
    {
        if ((x != 0 && Nat256.mul33WordAdd(PInv33, x, z, 0) != 0)
            || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat.add33To(8, PInv33, z);
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
            Nat.sub33From(8, PInv33, z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.sub(16, xx, yy, zz);
        if (c != 0)
        {
            if (Nat.subFrom(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.decAt(16, zz, PExtInv.length);
            }
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(8, x, 0, z);
        if (c != 0 || (z[7] == P7 && Nat256.gte(z, P)))
        {
            Nat.add33To(8, PInv33, z);
        }
    }
}
