package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat576;

public class SecT571Field
{
    private static final long M59 = -1L >>> 5;

    private static final long RM = 0xEF7BDEF7BDEF7BDEL;

    private static final long[] ROOT_Z = new long[]{ 0x2BE1195F08CAFB99L, 0x95F08CAF84657C23L, 0xCAF84657C232BE11L, 0x657C232BE1195F08L,
        0xF84657C2308CAF84L, 0x7C232BE1195F08CAL, 0xBE1195F08CAF8465L, 0x5F08CAF84657C232L, 0x784657C232BE119L };

    public static void add(long[] x, long[] y, long[] z)
    {
        for (int i = 0; i < 9; ++i)
        {
            z[i] = x[i] ^ y[i];
        }
    }

    private static void add(long[] x, int xOff, long[] y, int yOff, long[] z, int zOff)
    {
        for (int i = 0; i < 9; ++i)
        {
            z[zOff + i] = x[xOff + i] ^ y[yOff + i];
        }
    }

    private static void addBothTo(long[] x, int xOff, long[] y, int yOff, long[] z, int zOff)
    {
        for (int i = 0; i < 9; ++i)
        {
            z[zOff + i] ^= x[xOff + i] ^ y[yOff + i];
        }
    }

    public static void addExt(long[] xx, long[] yy, long[] zz)
    {
        for (int i = 0; i < 18; ++i)
        {
            zz[i] = xx[i] ^ yy[i];
        }
    }

    public static void addOne(long[] x, long[] z)
    {
        z[0] = x[0] ^ 1L;
        for (int i = 1; i < 9; ++i)
        {
            z[i] = x[i];
        }
    }

    public static long[] fromBigInteger(BigInteger x)
    {
        long[] z = Nat576.fromBigInteger64(x);
        reduce5(z, 0);
        return z;
    }

    public static void invert(long[] x, long[] z)
    {
        if (Nat576.isZero64(x))
        {
            throw new IllegalStateException();
        }

        // Itoh-Tsujii inversion with bases { 2, 3, 5 }

        long[] t0 = Nat576.create64();
        long[] t1 = Nat576.create64();
        long[] t2 = Nat576.create64();

        square(x, t2);

        // 5 | 570
        square(t2, t0);
        square(t0, t1);
        multiply(t0, t1, t0);
        squareN(t0, 2, t1);
        multiply(t0, t1, t0);
        multiply(t0, t2, t0);

        // 3 | 114
        squareN(t0, 5, t1);
        multiply(t0, t1, t0);
        squareN(t1, 5, t1);
        multiply(t0, t1, t0);

        // 2 | 38
        squareN(t0, 15, t1);
        multiply(t0, t1, t2);

        // ! {2,3,5} | 19
        squareN(t2, 30, t0);
        squareN(t0, 30, t1);
        multiply(t0, t1, t0);

        // 3 | 9
        squareN(t0, 60, t1);
        multiply(t0, t1, t0);
        squareN(t1, 60, t1);
        multiply(t0, t1, t0);

        // 3 | 3
        squareN(t0, 180, t1);
        multiply(t0, t1, t0);
        squareN(t1, 180, t1);
        multiply(t0, t1, t0);

        multiply(t0, t2, z);
    }

    public static void multiply(long[] x, long[] y, long[] z)
    {
        long[] tt = Nat576.createExt64();
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(long[] x, long[] y, long[] zz)
    {
        long[] tt = Nat576.createExt64();
        implMultiply(x, y, tt);
        addExt(zz, tt, zz);
    }

    public static void reduce(long[] xx, long[] z)
    {
        long xx09 = xx[9];
        long u = xx[17], v = xx09;

        xx09  = v ^ (u >>> 59) ^ (u >>> 57) ^ (u >>> 54) ^ (u >>> 49);
        v = xx[8] ^ (u <<   5) ^ (u <<   7) ^ (u <<  10) ^ (u <<  15);

        for (int i = 16; i >= 10; --i)
        {
            u = xx[i];
            z[i - 8]  = v ^ (u >>> 59) ^ (u >>> 57) ^ (u >>> 54) ^ (u >>> 49);
            v = xx[i - 9] ^ (u <<   5) ^ (u <<   7) ^ (u <<  10) ^ (u <<  15);
        }

        u = xx09;
        z[1]  = v ^ (u >>> 59) ^ (u >>> 57) ^ (u >>> 54) ^ (u >>> 49);
        v = xx[0] ^ (u <<   5) ^ (u <<   7) ^ (u <<  10) ^ (u <<  15);

        long x08 = z[8];
        long t   = x08 >>> 59;
        z[0]     = v ^ t ^ (t << 2) ^ (t << 5) ^ (t << 10);
        z[8]     = x08 & M59;
    }

    public static void reduce5(long[] z, int zOff)
    {
        long z8      = z[zOff + 8], t = z8 >>> 59;
        z[zOff    ] ^= t ^ (t << 2) ^ (t << 5) ^ (t << 10);
        z[zOff + 8]  = z8 & M59;
    }

    public static void sqrt(long[] x, long[] z)
    {
        long[] evn = Nat576.create64(), odd = Nat576.create64();

        int pos = 0;
        for (int i = 0; i < 4; ++i)
        {
            long u0 = Interleave.unshuffle(x[pos++]);
            long u1 = Interleave.unshuffle(x[pos++]);
            evn[i] = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
            odd[i] = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);
        }
        {
            long u0 = Interleave.unshuffle(x[pos]);
            evn[4] = (u0 & 0x00000000FFFFFFFFL);
            odd[4] = (u0 >>> 32);
        }

        multiply(odd, ROOT_Z, z);
        add(z, evn, z);
    }

    public static void square(long[] x, long[] z)
    {
        long[] tt = Nat576.createExt64();
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz)
    {
        long[] tt = Nat576.createExt64();
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z)
    {
//        assert n > 0;

        long[] tt = Nat576.createExt64();
        implSquare(x, tt);
        reduce(tt, z);

        while (--n > 0)
        {
            implSquare(z, tt);
            reduce(tt, z);
        }
    }

    public static int trace(long[] x)
    {
        // Non-zero-trace bits: 0, 561, 569
        return (int)(x[0] ^ (x[8] >>> 49) ^ (x[8] >>> 57)) & 1;
    }

    protected static void implMultiply(long[] x, long[] y, long[] zz)
    {
//        for (int i = 0; i < 9; ++i)
//        {
//            implMulwAcc(x, y[i], zz, i);
//        }

        /*
         * Precompute table of all 4-bit products of y
         */
        long[] T0 = new long[9 << 4];
        System.arraycopy(y, 0, T0, 9, 9);
//        reduce5(T0, 9);
        int tOff = 0;
        for (int i = 7; i > 0; --i)
        {
            tOff += 18;
            Nat.shiftUpBit64(9, T0, tOff >>> 1, 0L, T0, tOff);
            reduce5(T0, tOff);
            add(T0, 9, T0, tOff, T0, tOff + 9);
        }

        /*
         * Second table with all 4-bit products of B shifted 4 bits
         */
        long[] T1 = new long[T0.length];
        Nat.shiftUpBits64(T0.length, T0, 0, 4, 0L, T1, 0);

        int MASK = 0xF;

        /*
         * Lopez-Dahab algorithm
         */

        for (int k = 56; k >= 0; k -= 8)
        {
            for (int j = 1; j < 9; j += 2)
            {
                int aVal = (int)(x[j] >>> k);
                int u = aVal & MASK;
                int v = (aVal >>> 4) & MASK;
                addBothTo(T0, 9 * u, T1, 9 * v, zz, j - 1);
            }
            Nat.shiftUpBits64(16, zz, 0, 8, 0L);
        }

        for (int k = 56; k >= 0; k -= 8)
        {
            for (int j = 0; j < 9; j += 2)
            {
                int aVal = (int)(x[j] >>> k);
                int u = aVal & MASK;
                int v = (aVal >>> 4) & MASK;
                addBothTo(T0, 9 * u, T1, 9 * v, zz, j);
            }
            if (k > 0)
            {
                Nat.shiftUpBits64(18, zz, 0, 8, 0L);
            }
        }
    }

    protected static void implMulwAcc(long[] xs, long y, long[] z, int zOff)
    {
        long[] u = new long[32];
//      u[0] = 0;
        u[1] = y;
        for (int i = 2; i < 32; i += 2)
        {
            u[i    ] = u[i >>> 1] << 1;
            u[i + 1] = u[i      ] ^  y;
        }

        long l = 0;
        for (int i = 0; i < 9; ++i)
        {
            long x = xs[i];

            int j = (int)x;

            l ^= u[j & 31];

            long g, h = 0;
            int k = 60;
            do
            {
                j  = (int)(x >>> k);
                g  = u[j & 31];
                l ^= (g <<   k);
                h ^= (g >>> -k);
            }
            while ((k -= 5) > 0);

            for (int p = 0; p < 4; ++p)
            {
                x = (x & RM) >>> 1;
                h ^= x & ((y << p) >> 63);
            }

            z[zOff + i] ^= l;

            l = h;
        }
        z[zOff + 9] ^= l;
    }

    protected static void implSquare(long[] x, long[] zz)
    {
        for (int i = 0; i < 9; ++i)
        {
            Interleave.expand64To128(x[i], zz, i << 1);
        }
    }
}
