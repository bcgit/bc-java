package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat192;

public class SecT163Field
{
    private static final long M35 = -1L >>> 29;
    private static final long M55 = -1L >>> 9;

    private static final long[] ROOT_Z = new long[]{ 0xB6DB6DB6DB6DB6B0L, 0x492492492492DB6DL, 0x492492492L };

    public static void add(long[] x, long[] y, long[] z)
    {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
    }

    public static void addExt(long[] xx, long[] yy, long[] zz)
    {
        zz[0] = xx[0] ^ yy[0];
        zz[1] = xx[1] ^ yy[1];
        zz[2] = xx[2] ^ yy[2];
        zz[3] = xx[3] ^ yy[3];
        zz[4] = xx[4] ^ yy[4];
        zz[5] = xx[5] ^ yy[5];
    }

    public static void addOne(long[] x, long[] z)
    {
        z[0] = x[0] ^ 1L;
        z[1] = x[1];
        z[2] = x[2];
    }

    private static void addTo(long[] x, long[] z)
    {
        z[0] ^= x[0];
        z[1] ^= x[1];
        z[2] ^= x[2];
    }

    public static long[] fromBigInteger(BigInteger x)
    {
        return Nat.fromBigInteger64(163, x);
    }

    public static void halfTrace(long[] x, long[] z)
    {
        long[] tt = Nat192.createExt64();

        Nat192.copy64(x, z);
        for (int i = 1; i < 163; i += 2)
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
        if (Nat192.isZero64(x))
        {
            throw new IllegalStateException();
        }

        // Itoh-Tsujii inversion with bases { 2, 3 }

        long[] t0 = Nat192.create64();
        long[] t1 = Nat192.create64();

        square(x, t0);

        // 3 | 162
        squareN(t0, 1, t1);
        multiply(t0, t1, t0);
        squareN(t1, 1, t1);
        multiply(t0, t1, t0);

        // 3 | 54
        squareN(t0, 3, t1);
        multiply(t0, t1, t0);
        squareN(t1, 3, t1);
        multiply(t0, t1, t0);

        // 3 | 18
        squareN(t0, 9, t1);
        multiply(t0, t1, t0);
        squareN(t1, 9, t1);
        multiply(t0, t1, t0);

        // 3 | 6
        squareN(t0, 27, t1);
        multiply(t0, t1, t0);
        squareN(t1, 27, t1);
        multiply(t0, t1, t0);

        // 2 | 2
        squareN(t0, 81, t1);
        multiply(t0, t1, z);
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
        long x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3], x4 = xx[4], x5 = xx[5];

        x2 ^= (x5 <<  29) ^ (x5 <<  32) ^ (x5 <<  35) ^ (x5 <<  36);
        x3 ^= (x5 >>> 35) ^ (x5 >>> 32) ^ (x5 >>> 29) ^ (x5 >>> 28);

        x1 ^= (x4 <<  29) ^ (x4 <<  32) ^ (x4 <<  35) ^ (x4 <<  36);
        x2 ^= (x4 >>> 35) ^ (x4 >>> 32) ^ (x4 >>> 29) ^ (x4 >>> 28);

        x0 ^= (x3 <<  29) ^ (x3 <<  32) ^ (x3 <<  35) ^ (x3 <<  36);
        x1 ^= (x3 >>> 35) ^ (x3 >>> 32) ^ (x3 >>> 29) ^ (x3 >>> 28);

        long t = x2 >>> 35;
        z[0]   = x0 ^ t ^ (t << 3) ^ (t << 6) ^ (t << 7);
        z[1]   = x1;
        z[2]   = x2 & M35;
    }

    public static void reduce29(long[] z, int zOff)
    {
        long z2      = z[zOff + 2], t = z2 >>> 35;
        z[zOff    ] ^= t ^ (t << 3) ^ (t << 6) ^ (t << 7);
        z[zOff + 2]  = z2 & M35;
    }

    public static void sqrt(long[] x, long[] z)
    {
        long[] odd = Nat192.create64();

        long u0, u1;
        u0 = Interleave.unshuffle(x[0]); u1 = Interleave.unshuffle(x[1]);
        long e0 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
        odd[0]  = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

        u0 = Interleave.unshuffle(x[2]);
        long e1 = (u0 & 0x00000000FFFFFFFFL);
        odd[1]  = (u0 >>> 32);

        multiply(odd, ROOT_Z, z);

        z[0] ^= e0;
        z[1] ^= e1;
    }

    public static void square(long[] x, long[] z)
    {
        long[] tt = Nat192.createExt64();
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz)
    {
        long[] tt = Nat192.createExt64();
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z)
    {
//        assert n > 0;

        long[] tt = Nat192.createExt64();
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
        // Non-zero-trace bits: 0, 157
        return (int)(x[0] ^ (x[2] >>> 29)) & 1;
    }

    protected static void implCompactExt(long[] zz)
    {
        long z0 = zz[0], z1 = zz[1], z2 = zz[2], z3 = zz[3], z4 = zz[4], z5 = zz[5];
        zz[0] =  z0         ^ (z1 << 55);
        zz[1] = (z1 >>>  9) ^ (z2 << 46);
        zz[2] = (z2 >>> 18) ^ (z3 << 37);
        zz[3] = (z3 >>> 27) ^ (z4 << 28);
        zz[4] = (z4 >>> 36) ^ (z5 << 19);
        zz[5] = (z5 >>> 45);
    }

    protected static void implMultiply(long[] x, long[] y, long[] zz)
    {
        /*
         * "Five-way recursion" as described in "Batch binary Edwards", Daniel J. Bernstein.
         */

        long f0 = x[0], f1 = x[1], f2 = x[2];
        f2  = ((f1 >>> 46) ^ (f2 << 18));
        f1  = ((f0 >>> 55) ^ (f1 <<  9)) & M55;
        f0 &= M55;

        long g0 = y[0], g1 = y[1], g2 = y[2];
        g2  = ((g1 >>> 46) ^ (g2 << 18));
        g1  = ((g0 >>> 55) ^ (g1 <<  9)) & M55;
        g0 &= M55;

        long[] u = zz;
        long[] H = new long[10];

        implMulw(u, f0, g0, H, 0);               // H(0)       55/54 bits
        implMulw(u, f2, g2, H, 2);               // H(INF)     55/50 bits

        long t0 = f0 ^ f1 ^ f2;
        long t1 = g0 ^ g1 ^ g2;

        implMulw(u, t0, t1, H, 4);               // H(1)       55/54 bits

        long t2 = (f1 << 1) ^ (f2 << 2);
        long t3 = (g1 << 1) ^ (g2 << 2);

        implMulw(u, f0 ^ t2, g0 ^ t3, H, 6);     // H(t)       55/56 bits
        implMulw(u, t0 ^ t2, t1 ^ t3, H, 8);     // H(t + 1)   55/56 bits

        long t4 = H[6] ^ H[8];
        long t5 = H[7] ^ H[9];

//        assert t5 >>> 55 == 0;

        // Calculate V
        long v0 =      (t4 << 1) ^ H[6];
        long v1 = t4 ^ (t5 << 1) ^ H[7];
        long v2 = t5;

        // Calculate U
        long u0 = H[0];
        long u1 = H[1] ^ H[0] ^ H[4];
        long u2 =        H[1] ^ H[5];

        // Calculate W
        long w0 = u0 ^ v0 ^ (H[2] << 4) ^ (H[2] << 1);
        long w1 = u1 ^ v1 ^ (H[3] << 4) ^ (H[3] << 1);
        long w2 = u2 ^ v2;

        // Propagate carries
        w1 ^= (w0 >>> 55); w0 &= M55;
        w2 ^= (w1 >>> 55); w1 &= M55;

//        assert (w0 & 1L) == 0;

        // Divide W by t

        w0 = (w0 >>> 1) ^ ((w1 & 1L) << 54);
        w1 = (w1 >>> 1) ^ ((w2 & 1L) << 54);
        w2 = (w2 >>> 1);

        // Divide W by (t + 1)

        w0 ^= (w0 << 1);
        w0 ^= (w0 << 2);
        w0 ^= (w0 << 4);
        w0 ^= (w0 << 8);
        w0 ^= (w0 << 16);
        w0 ^= (w0 << 32);

        w0 &= M55; w1 ^= (w0 >>> 54);

        w1 ^= (w1 << 1);
        w1 ^= (w1 << 2);
        w1 ^= (w1 << 4);
        w1 ^= (w1 << 8);
        w1 ^= (w1 << 16);
        w1 ^= (w1 << 32);

        w1 &= M55; w2 ^= (w1 >>> 54);

        w2 ^= (w2 << 1);
        w2 ^= (w2 << 2);
        w2 ^= (w2 << 4);
        w2 ^= (w2 << 8);
        w2 ^= (w2 << 16);
        w2 ^= (w2 << 32);

//        assert w2 >>> 52 == 0;

        zz[0] = u0;
        zz[1] = u1 ^ w0      ^ H[2];
        zz[2] = u2 ^ w1 ^ w0 ^ H[3];
        zz[3] =      w2 ^ w1;
        zz[4] =           w2 ^ H[2];
        zz[5] =                H[3];

        implCompactExt(zz);
    }

    protected static void implMulw(long[] u, long x, long y, long[] z, int zOff)
    {
//        assert x >>> 56 == 0;
//        assert y >>> 56 == 0;

//      u[0] = 0;
        u[1] = y;
        u[2] = u[1] << 1;
        u[3] = u[2] ^  y;
        u[4] = u[2] << 1;
        u[5] = u[4] ^  y;
        u[6] = u[3] << 1;
        u[7] = u[6] ^  y;

        int j = (int)x;
        long g, h = 0, l = u[j & 3];
        int k = 47;
        do
        {
            j  = (int)(x >>> k);
            g  = u[j & 7]
               ^ u[(j >>> 3) & 7] << 3
               ^ u[(j >>> 6) & 7] << 6;
            l ^= (g <<   k);
            h ^= (g >>> -k);
        }
        while ((k -= 9) > 0);

//        assert h >>> 47 == 0;

        z[zOff    ] = l & M55;
        z[zOff + 1] = (l >>> 55) ^ (h << 9);
    }

    protected static void implSquare(long[] x, long[] zz)
    {
        Interleave.expand64To128(x, 0, 3, zz, 0);
    }
}
