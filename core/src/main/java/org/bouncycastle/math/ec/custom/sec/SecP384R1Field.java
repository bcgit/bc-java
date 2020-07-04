package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat384;
import org.bouncycastle.util.Pack;

public class SecP384R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^384 - 2^128 - 2^96 + 2^32 - 1
    static final int[] P = new int[]{ 0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    static final int[] PExt = new int[]{ 0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000, 0xFFFFFFFE,
        0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0x00000001, 0x00000000,
        0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
    private static final int[] PExtInv = new int[]{ 0xFFFFFFFF, 0x00000001, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF, 0x00000001,
        0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFE, 0xFFFFFFFF,
        0x00000001, 0x00000002 };
    private static final int P11 = 0xFFFFFFFF;
    private static final int PExt23 = 0xFFFFFFFF;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat.add(12, x, y, z);
        if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.add(24, xx, yy, zz);
        if (c != 0 || (zz[23] == PExt23 && Nat.gte(24, zz, PExt)))
        {
            if (Nat.addTo(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.incAt(24, zz, PExtInv.length);
            }
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(12, x, z);
        if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
        {
            addPInvTo(z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat.fromBigInteger(384, x);
        if (z[11] == P11 && Nat.gte(12, z, P))
        {
            Nat.subFrom(12, P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat.shiftDownBit(12, x, 0, z);
        }
        else
        {
            int c = Nat.add(12, x, P, z);
            Nat.shiftDownBit(12, z, c);
        }
    }

    public static void inv(int[] x, int[] z)
    {
        /*
         * Raise this element to the exponent 2^384 - 2^128 - 2^96 + 2^32 - 3
         *
         * Breaking up the exponent's binary representation into "repunits", we get:
         * { 255 1s } { 1 0s } { 32 1s } { 64 0s } { 30 1s } { 1 0s} { 1 1s}
         *
         * Therefore we need an addition chain containing 1, 30, 32, 255 (the lengths of the repunits)
         * We use: [1], 2, 3, 6, 12, 24, [30], [32], 62, 124, 248, 254, [255]
         */

        if (0 != isZero(x))
        {
            throw new IllegalArgumentException("'x' cannot be 0");
        }

        int[] x1 = x;
        int[] x2 = Nat.create(12);
        square(x1, x2);
        multiply(x2, x1, x2);
        int[] x3 = Nat.create(12);
        square(x2, x3);
        multiply(x3, x1, x3);
        int[] x6 = Nat.create(12);
        squareN(x3, 3, x6);
        multiply(x6, x3, x6);
        int[] x12 = x3;
        squareN(x6, 6, x12);
        multiply(x12, x6, x12);
        int[] x24 = Nat.create(12);
        squareN(x12, 12, x24);
        multiply(x24, x12, x24);
        int[] x30 = x12;
        squareN(x24, 6, x30);
        multiply(x30, x6, x30);
        int[] x32 = x24;
        squareN(x30, 2, x32);
        multiply(x32, x2, x32);
        int[] x62 = x2;
        squareN(x32, 30, x62);
        multiply(x62, x30, x62);
        int[] x124 = Nat.create(12);
        squareN(x62, 62, x124);
        multiply(x124, x62, x124);
        int[] x248 = x62;
        squareN(x124, 124, x248);
        multiply(x248, x124, x248);
        int[] x254 = x124;
        squareN(x248, 6, x254);
        multiply(x254, x6, x254);
        int[] x255 = x6;
        square(x254, x255);
        multiply(x255, x1, x255);

        int[] t = x255;
        squareN(t, 33, t);
        multiply(t, x32, t);
        squareN(t, 94, t);
        multiply(t, x30, t);
        squareN(t, 2, t);

        // NOTE that x1 and z could be the same array
        multiply(x1, t, z);
    }

    public static int isZero(int[] x)
    {
        int d = 0;
        for (int i = 0; i < 12; ++i)
        {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat.create(24);
        Nat384.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z)
    {
        if (0 != isZero(x))
        {
            Nat.sub(12, P, P, z);
        }
        else
        {
            Nat.sub(12, P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z)
    {
        byte[] bb = new byte[12 * 4];
        do
        {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 12);
        }
        while (0 == Nat.lessThan(12, z, P));
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
        long xx16 = xx[16] & M, xx17 = xx[17] & M, xx18 = xx[18] & M, xx19 = xx[19] & M;
        long xx20 = xx[20] & M, xx21 = xx[21] & M, xx22 = xx[22] & M, xx23 = xx[23] & M;

        final long n = 1;

        long t0 = (xx[12] & M) + xx20 - n;
        long t1 = (xx[13] & M) + xx22;
        long t2 = (xx[14] & M) + xx22 + xx23;
        long t3 = (xx[15] & M) + xx23;
        long t4 = xx17 + xx21;
        long t5 = xx21 - xx23;
        long t6 = xx22 - xx23;
        long t7 = t0 + t5;

        long cc = 0;
        cc += (xx[0] & M) + t7;
        z[0] = (int)cc;
        cc >>= 32;
        cc += (xx[1] & M) + xx23 - t0 + t1;
        z[1] = (int)cc;
        cc >>= 32;
        cc += (xx[2] & M) - xx21 - t1 + t2;
        z[2] = (int)cc;
        cc >>= 32;
        cc += (xx[3] & M) - t2 + t3 + t7;
        z[3] = (int)cc;
        cc >>= 32;
        cc += (xx[4] & M) + xx16 + xx21 + t1 - t3 + t7;
        z[4] = (int)cc;
        cc >>= 32;
        cc += (xx[5] & M) - xx16 + t1 + t2 + t4;
        z[5] = (int)cc;
        cc >>= 32;
        cc += (xx[6] & M) + xx18 - xx17 + t2 + t3;
        z[6] = (int)cc;
        cc >>= 32;
        cc += (xx[7] & M) + xx16 + xx19 - xx18 + t3;
        z[7] = (int)cc;
        cc >>= 32;
        cc += (xx[8] & M) + xx16 + xx17 + xx20 - xx19;
        z[8] = (int)cc;
        cc >>= 32;
        cc += (xx[9] & M) + xx18 - xx20 + t4;
        z[9] = (int)cc;
        cc >>= 32;
        cc += (xx[10] & M) + xx18 + xx19 - t5 + t6;
        z[10] = (int)cc;
        cc >>= 32;
        cc += (xx[11] & M) + xx19 + xx20 - t6;
        z[11] = (int)cc;
        cc >>= 32;
        cc += n;

//        assert cc >= 0;

        reduce32((int)cc, z);
    }

    public static void reduce32(int x, int[] z)
    {
        long cc = 0;

        if (x != 0)
        {
            long xx12 = x & M;

            cc += (z[0] & M) + xx12;
            z[0] = (int)cc;
            cc >>= 32;
            cc += (z[1] & M) - xx12;
            z[1] = (int)cc;
            cc >>= 32;
            if (cc != 0)
            {
                cc += (z[2] & M);
                z[2] = (int)cc;
                cc >>= 32;
            }
            cc += (z[3] & M) + xx12;
            z[3] = (int)cc;
            cc >>= 32;
            cc += (z[4] & M) + xx12;
            z[4] = (int)cc;
            cc >>= 32;

//            assert cc == 0 || cc == 1;
        }

        if ((cc != 0 && Nat.incAt(12, z, 5) != 0)
            || (z[11] == P11 && Nat.gte(12, z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat.create(24);
        Nat384.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat.create(24);
        Nat384.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat384.square(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat.sub(12, x, y, z);
        if (c != 0)
        {
            subPInvFrom(z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.sub(24, xx, yy, zz);
        if (c != 0)
        {
            if (Nat.subFrom(PExtInv.length, PExtInv, zz) != 0)
            {
                Nat.decAt(24, zz, PExtInv.length);
            }
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(12, x, 0, z);
        if (c != 0 || (z[11] == P11 && Nat.gte(12, z, P)))
        {
            addPInvTo(z);
        }
    }

    private static void addPInvTo(int[] z)
    {
        long c = (z[0] & M) + 1;
        z[0] = (int)c;
        c >>= 32;
        c += (z[1] & M) - 1;
        z[1] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            c += (z[2] & M);
            z[2] = (int)c;
            c >>= 32;
        }
        c += (z[3] & M) + 1;
        z[3] = (int)c;
        c >>= 32;
        c += (z[4] & M) + 1;
        z[4] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            Nat.incAt(12, z, 5);
        }
    }

    private static void subPInvFrom(int[] z)
    {
        long c = (z[0] & M) - 1;
        z[0] = (int)c;
        c >>= 32;
        c += (z[1] & M) + 1;
        z[1] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            c += (z[2] & M);
            z[2] = (int)c;
            c >>= 32;
        }
        c += (z[3] & M) - 1;
        z[3] = (int)c;
        c >>= 32;
        c += (z[4] & M) - 1;
        z[4] = (int)c;
        c >>= 32;
        if (c != 0)
        {
            Nat.decAt(12, z, 5);
        }
    }
}
