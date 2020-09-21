package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat128;

public class SecT113Field
{
    private static final long M49 = -1L >>> 15;
    private static final long M57 = -1L >>> 7;

    public static void add(long[] x, long[] y, long[] z)
    {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
    }

    public static void addExt(long[] xx, long[] yy, long[] zz)
    {
        zz[0] = xx[0] ^ yy[0];
        zz[1] = xx[1] ^ yy[1];
        zz[2] = xx[2] ^ yy[2];
        zz[3] = xx[3] ^ yy[3];
    }

    public static void addOne(long[] x, long[] z)
    {
        z[0] = x[0] ^ 1L;
        z[1] = x[1];
    }

    private static void addTo(long[] x, long[] z)
    {
        z[0] ^= x[0];
        z[1] ^= x[1];
    }

    public static long[] fromBigInteger(BigInteger x)
    {
        return Nat.fromBigInteger64(113, x);
    }

    public static void halfTrace(long[] x, long[] z)
    {
        long[] tt = Nat128.createExt64();

        Nat128.copy64(x, z);
        for (int i = 1; i < 113; i += 2)
        {
            implSquare(z, tt);
            reduce(tt, z);
            implSquare(z, tt);
            reduce(tt, z);
            addTo(x, z);
        }
    }

    public static void invert(long[] x, long[] z)
    {
        if (Nat128.isZero64(x))
        {
            throw new IllegalStateException();
        }

        // Itoh-Tsujii inversion

        long[] t0 = Nat128.create64();
        long[] t1 = Nat128.create64();

        square(x, t0);
        multiply(t0, x, t0);
        square(t0, t0);
        multiply(t0, x, t0);
        squareN(t0, 3, t1);
        multiply(t1, t0, t1);
        square(t1, t1);
        multiply(t1, x, t1);
        squareN(t1, 7, t0);
        multiply(t0, t1, t0);
        squareN(t0, 14, t1);
        multiply(t1, t0, t1);
        squareN(t1, 28, t0);
        multiply(t0, t1, t0);
        squareN(t0, 56, t1);
        multiply(t1, t0, t1);
        square(t1, z);
    }

    public static void multiply(long[] x, long[] y, long[] z)
    {
        long[] tt = new long[8];
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(long[] x, long[] y, long[] zz)
    {
        long[] tt = new long[8];
        implMultiply(x, y, tt);
        addExt(zz, tt, zz);
    }

    public static void reduce(long[] xx, long[] z)
    {
        long x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3];

        x1 ^= (x3 <<  15) ^ (x3 <<  24);
        x2 ^= (x3 >>> 49) ^ (x3 >>> 40);

        x0 ^= (x2 <<  15) ^ (x2 <<  24);
        x1 ^= (x2 >>> 49) ^ (x2 >>> 40);

        long t = x1 >>> 49;
        z[0]   = x0 ^ t ^ (t << 9);
        z[1]   = x1 & M49;
    }

    public static void reduce15(long[] z, int zOff)
    {
        long z1      = z[zOff + 1], t = z1 >>> 49;
        z[zOff    ] ^= t ^ (t << 9);
        z[zOff + 1]  = z1 & M49;
    }

    public static void sqrt(long[] x, long[] z)
    {
        long u0 = Interleave.unshuffle(x[0]), u1 = Interleave.unshuffle(x[1]);
        long e0 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
        long c0  = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

        z[0] = e0 ^ (c0 << 57) ^ (c0 << 5);
        z[1] =      (c0 >>> 7) ^ (c0 >>> 59); 
    }

    public static void square(long[] x, long[] z)
    {
        long[] tt = Nat128.createExt64();
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz)
    {
        long[] tt = Nat128.createExt64();
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z)
    {
//        assert n > 0;

        long[] tt = Nat128.createExt64();
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
        // Non-zero-trace bits: 0
        return (int)(x[0]) & 1;
    }

    protected static void implMultiply(long[] x, long[] y, long[] zz)
    {
        /*
         * "Three-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
         */

        long f0 = x[0], f1 = x[1];
        f1  = ((f0 >>> 57) ^ (f1 <<  7)) & M57;
        f0 &= M57;

        long g0 = y[0], g1 = y[1];
        g1  = ((g0 >>> 57) ^ (g1 <<  7)) & M57;
        g0 &= M57;

        long[] u = zz;
        long[] H = new long[6];

        implMulw(u, f0, g0, H, 0);              // H(0)       57/56 bits
        implMulw(u, f1, g1, H, 2);              // H(INF)     57/54 bits
        implMulw(u, f0 ^ f1, g0 ^ g1, H, 4);    // H(1)       57/56 bits

        long r  = H[1] ^ H[2];
        long z0 = H[0],
             z3 = H[3],
             z1 = H[4] ^ z0 ^ r,
             z2 = H[5] ^ z3 ^ r;

        zz[0] =  z0         ^ (z1 << 57);
        zz[1] = (z1 >>>  7) ^ (z2 << 50);
        zz[2] = (z2 >>> 14) ^ (z3 << 43);
        zz[3] = (z3 >>> 21);
    }

    protected static void implMulw(long[] u, long x, long y, long[] z, int zOff)
    {
//        assert x >>> 57 == 0;
//        assert y >>> 57 == 0;

//      u[0] = 0;
        u[1] = y;
        u[2] = u[1] << 1;
        u[3] = u[2] ^ y;
        u[4] = u[2] << 1;
        u[5] = u[4] ^ y;
        u[6] = u[3] << 1;
        u[7] = u[6] ^ y;

        int j = (int)x;
        long g, h = 0, l = u[j & 7];
        int k = 48;
        do
        {
            j  = (int)(x >>> k);
            g  = u[j & 7]
               ^ u[(j >>> 3) & 7] << 3
               ^ u[(j >>> 6) & 7] << 6;
            l ^= (g << k);
            h ^= (g >>> -k);
        }
        while ((k -= 9) > 0);

        h ^= ((x & 0x0100804020100800L) & ((y << 7) >> 63)) >>> 8;

//        assert h >>> 49 == 0;

        z[zOff    ] = l & M57;
        z[zOff + 1] = (l >>> 57) ^ (h << 7);
    }

    protected static void implSquare(long[] x, long[] zz)
    {
        Interleave.expand64To128(x, 0, 2, zz, 0);
    }
}
