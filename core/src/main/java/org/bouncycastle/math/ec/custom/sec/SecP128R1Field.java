package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat128;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Pack;

public class SecP128R1Field
{
    private static final long M = 0xFFFFFFFFL;

    // 2^128 - 2^97 - 1
    static final int[] P = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD };
    private static final int[] PExt = new int[]{ 0x00000001, 0x00000000, 0x00000000, 0x00000004, 0xFFFFFFFE, 0xFFFFFFFF,
        0x00000003, 0xFFFFFFFC };
    private static final int[] PExtInv = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFB, 0x00000001,
        0x00000000, 0xFFFFFFFC, 0x00000003 };
    private static final int P3s1 = 0xFFFFFFFD >>> 1;
    private static final int PExt7s1 = 0xFFFFFFFC >>> 1;

    public static void add(int[] x, int[] y, int[] z)
    {
        int c = Nat128.add(x, y, z);
        if (c != 0 || ((z[3] >>> 1) >= P3s1 && Nat128.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static void addExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat256.add(xx, yy, zz);
        if (c != 0 || ((zz[7] >>> 1) >= PExt7s1 && Nat256.gte(zz, PExt)))
        {
            Nat.addTo(PExtInv.length, PExtInv, zz);
        }
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(4, x, z);
        if (c != 0 || ((z[3] >>> 1) >= P3s1 && Nat128.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    public static int[] fromBigInteger(BigInteger x)
    {
        int[] z = Nat128.fromBigInteger(x);
        if ((z[3] >>> 1) >= P3s1 && Nat128.gte(z, P))
        {
            Nat128.subFrom(P, z);
        }
        return z;
    }

    public static void half(int[] x, int[] z)
    {
        if ((x[0] & 1) == 0)
        {
            Nat.shiftDownBit(4, x, 0, z);
        }
        else
        {
            int c = Nat128.add(x, P, z);
            Nat.shiftDownBit(4, z, c);
        }
    }

    public static void inv(int[] x, int[] z)
    {
        /*
         * Raise this element to the exponent 2^128 - 2^97 - 3
         *
         * Breaking up the exponent's binary representation into "repunits", we get:
         * { 30 1s } { 1 0s } { 95 1s } { 1 0s } { 1 1s }
         *
         * We use an addition chain for the beginning: [1], 2, 3, [5], 10, 20, [30]
         */

        if (0 != isZero(x))
        {
            throw new IllegalArgumentException("'x' cannot be 0");
        }

        int[] x1 = x;
        int[] x2 = Nat128.create();
        square(x1, x2);
        multiply(x2, x1, x2);
        int[] x3 = Nat128.create();
        square(x2, x3);
        multiply(x3, x1, x3);
        int[] x5 = x3;
        squareN(x3, 2, x5);
        multiply(x5, x2, x5);
        int[] x10 = x2;
        squareN(x5, 5, x10);
        multiply(x10, x5, x10);
        int[] x20 = Nat128.create();
        squareN(x10, 10, x20);
        multiply(x20, x10, x20);
        int[] x30 = x20;
        squareN(x20, 10, x30);
        multiply(x30, x10, x30);

        int[] t = x10;
        squareN(x30, 31, t);
        multiply(t, x30, t);
        squareN(t, 30, t);
        multiply(t, x30, t);
        squareN(t, 30, t);
        multiply(t, x30, t);
        squareN(t, 5, t);
        multiply(t, x5, t);
        squareN(t, 2, t);

        // NOTE that x1 and z could be the same array
        multiply(x1, t, z);
    }

    public static int isZero(int[] x)
    {
        int d = 0;
        for (int i = 0; i < 4; ++i)
        {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat128.createExt();
        Nat128.mul(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(int[] x, int[] y, int[] zz)
    {
        int c = Nat128.mulAddTo(x, y, zz);
        if (c != 0 || ((zz[7] >>> 1) >= PExt7s1 && Nat256.gte(zz, PExt)))
        {
            Nat.addTo(PExtInv.length, PExtInv, zz);
        }
    }

    public static void negate(int[] x, int[] z)
    {
        if (0 != isZero(x))
        {
            Nat128.sub(P, P, z);
        }
        else
        {
            Nat128.sub(P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z)
    {
        byte[] bb = new byte[4 * 4];
        do
        {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 4);
        }
        while (0 == Nat.lessThan(4, z, P));
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
        long x0 = xx[0] & M, x1 = xx[1] & M, x2 = xx[2] & M, x3 = xx[3] & M;
        long x4 = xx[4] & M, x5 = xx[5] & M, x6 = xx[6] & M, x7 = xx[7] & M;

        x3 += x7; x6 += (x7 << 1);
        x2 += x6; x5 += (x6 << 1);
        x1 += x5; x4 += (x5 << 1);
        x0 += x4; x3 += (x4 << 1);

        z[0] = (int)x0; x1 += (x0 >>> 32);
        z[1] = (int)x1; x2 += (x1 >>> 32);
        z[2] = (int)x2; x3 += (x2 >>> 32);
        z[3] = (int)x3;

        reduce32((int)(x3 >>> 32), z);
    }

    public static void reduce32(int x, int[] z)
    {
        while (x != 0)
        {
            long c, x4 = x & M;

            c = (z[0] & M) + x4;
            z[0] = (int)c; c >>= 32;
            if (c != 0)
            {
                c += (z[1] & M);
                z[1] = (int)c; c >>= 32;
                c += (z[2] & M);
                z[2] = (int)c; c >>= 32;
            }
            c += (z[3] & M) + (x4 << 1);
            z[3] = (int)c; c >>= 32;

//            assert c >= 0 && c <= 2;

            x = (int)c;
        }

        if ((z[3] >>> 1) >= P3s1 && Nat128.gte(z, P))
        {
            addPInvTo(z);
        }
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat128.createExt();
        Nat128.square(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat128.createExt();
        Nat128.square(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            Nat128.square(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat128.sub(x, y, z);
        if (c != 0)
        {
            subPInvFrom(z);
        }
    }

    public static void subtractExt(int[] xx, int[] yy, int[] zz)
    {
        int c = Nat.sub(10, xx, yy, zz);
        if (c != 0)
        {
            Nat.subFrom(PExtInv.length, PExtInv, zz);
        }
    }

    public static void twice(int[] x, int[] z)
    {
        int c = Nat.shiftUpBit(4, x, 0, z);
        if (c != 0 || ((z[3] >>> 1) >= P3s1 && Nat128.gte(z, P)))
        {
            addPInvTo(z);
        }
    }

    private static void addPInvTo(int[] z)
    {
        long c = (z[0] & M) + 1;
        z[0] = (int)c; c >>= 32;
        if (c != 0)
        {
            c += (z[1] & M);
            z[1] = (int)c; c >>= 32;
            c += (z[2] & M);
            z[2] = (int)c; c >>= 32;
        }
        c += (z[3] & M) + 2;
        z[3] = (int)c;
    }

    private static void subPInvFrom(int[] z)
    {
        long c = (z[0] & M) - 1;
        z[0] = (int)c; c >>= 32;
        if (c != 0)
        {
            c += (z[1] & M);
            z[1] = (int)c; c >>= 32;
            c += (z[2] & M);
            z[2] = (int)c; c >>= 32;
        }
        c += (z[3] & M) - 2;
        z[3] = (int)c;
    }
}
