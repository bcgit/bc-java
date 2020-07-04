package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat512;
import org.bouncycastle.util.Pack;

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
            c += Nat.inc(16, z);
            c &= P16;
        }
        z[16] = c;
    }

    public static void addOne(int[] x, int[] z)
    {
        int c = Nat.inc(16, x, z) + x[16];
        if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
        {
            c += Nat.inc(16, z);
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
        int x16 = x[16];
        int c = Nat.shiftDownBit(16, x, x16, z);
        z[16] = (x16 >>> 1) | (c >>> 23);
    }

    public static void inv(int[] x, int[] z)
    {
        /*
         * Raise this element to the exponent 2^521 - 3
         *
         * Breaking up the exponent's binary representation into "repunits", we get:
         * { 519 1s } { 1 0s} { 1 1s}
         *
         * Therefore we need an addition chain containing 1, 519 (the lengths of the repunits)
         * We use: [1], 2, 4, 8, 16, 32, 64, 128, 256, 512, 516, 518, [519]
         */

        if (0 != isZero(x))
        {
            throw new IllegalArgumentException("'x' cannot be 0");
        }

        int[] x1 = x;
        int[] x2 = Nat.create(17);
        square(x1, x2);
        multiply(x2, x1, x2);
        int[] x4 = Nat.create(17);
        squareN(x2, 2, x4);
        multiply(x4, x2, x4);
        int[] x8 = Nat.create(17);
        squareN(x4, 4, x8);
        multiply(x8, x4, x8);
        int[] x16 = Nat.create(17);
        squareN(x8, 8, x16);
        multiply(x16, x8, x16);
        int[] x32 = x8;
        squareN(x16, 16, x32);
        multiply(x32, x16, x32);
        int[] x64 = x16;
        squareN(x32, 32, x64);
        multiply(x64, x32, x64);
        int[] x128 = x32;
        squareN(x64, 64, x128);
        multiply(x128, x64, x128);
        int[] x256 = x64;
        squareN(x128, 128, x256);
        multiply(x256, x128, x256);
        int[] x512 = x128;
        squareN(x256, 256, x512);
        multiply(x512, x256, x512);
        int[] x516 = x256;
        squareN(x512, 4, x516);
        multiply(x516, x4, x516);
        int[] x518 = x4;
        squareN(x516, 2, x518);
        multiply(x518, x2, x518);
        int[] x519 = x2;
        square(x518, x519);
        multiply(x519, x1, x519);

        int[] t = x519;
        squareN(t, 2, t);

        // NOTE that x1 and z could be the same array
        multiply(x1, t, z);
    }

    public static int isZero(int[] x)
    {
        int d = 0;
        for (int i = 0; i < 17; ++i)
        {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static void multiply(int[] x, int[] y, int[] z)
    {
        int[] tt = Nat.create(33);
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void negate(int[] x, int[] z)
    {
        if (0 != isZero(x))
        {
            Nat.sub(17, P, P, z);
        }
        else
        {
            Nat.sub(17, P, x, z);
        }
    }

    public static void random(SecureRandom r, int[] z)
    {
        byte[] bb = new byte[17 * 4];
        do
        {
            r.nextBytes(bb);
            Pack.littleEndianToInt(bb, 0, z, 0, 17);
            z[16] &= 0x000001FFL;
        }
        while (0 == Nat.lessThan(17, z, P));
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
//        assert xx[32] >>> 18 == 0;

        int xx32 = xx[32];
        int c = Nat.shiftDownBits(16, xx, 16, 9, xx32, z, 0) >>> 23;
        c += xx32 >>> 9;
        c += Nat.addTo(16, xx, z);
        if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
        {
            c += Nat.inc(16, z);
            c &= P16;
        }
        z[16] = c;
    }

    public static void reduce23(int[] z)
    {
        int z16 = z[16];
        int c = Nat.addWordTo(16, z16 >>> 9, z) + (z16 & P16);
        if (c > P16 || (c == P16 && Nat.eq(16, z, P)))
        {
            c += Nat.inc(16, z);
            c &= P16;
        }
        z[16] = c;
    }

    public static void square(int[] x, int[] z)
    {
        int[] tt = Nat.create(33);
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareN(int[] x, int n, int[] z)
    {
//        assert n > 0;

        int[] tt = Nat.create(33);
        implSquare(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            implSquare(z, tt);
            reduce(tt, z);
        }
    }

    public static void subtract(int[] x, int[] y, int[] z)
    {
        int c = Nat.sub(16, x, y, z) + x[16] - y[16];
        if (c < 0)
        {
            c += Nat.dec(16, z);
            c &= P16;
        }
        z[16] = c;
    }

    public static void twice(int[] x, int[] z)
    {
        int x16 = x[16];
        int c = Nat.shiftUpBit(16, x, x16 << 23, z) | (x16 << 1);
        z[16] = c & P16;
    }

    protected static void implMultiply(int[] x, int[] y, int[] zz)
    {
        Nat512.mul(x, y, zz);

        int x16 = x[16], y16 = y[16];
        zz[32] = Nat.mul31BothAdd(16, x16, y, y16, x, zz, 16) + (x16 * y16);
    }

    protected static void implSquare(int[] x, int[] zz)
    {
        Nat512.square(x, zz);

        int x16 = x[16];
        zz[32] = Nat.mulWordAddTo(16, x16 << 1, x, 0, zz, 16) + (x16 * x16);
    }
}
