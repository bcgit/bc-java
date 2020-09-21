package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat320;

public class SecT283Field
{
    private static final long M27 = -1L >>> 37;
    private static final long M57 = -1L >>> 7;

    private static final long[] ROOT_Z = new long[]{ 0x0C30C30C30C30808L, 0x30C30C30C30C30C3L, 0x820820820820830CL,
        0x0820820820820820L, 0x2082082L };

    public static void add(long[] x, long[] y, long[] z)
    {
        z[0] = x[0] ^ y[0];
        z[1] = x[1] ^ y[1];
        z[2] = x[2] ^ y[2];
        z[3] = x[3] ^ y[3];
        z[4] = x[4] ^ y[4];
    }

    public static void addExt(long[] xx, long[] yy, long[] zz)
    {
        zz[0] = xx[0] ^ yy[0];
        zz[1] = xx[1] ^ yy[1];
        zz[2] = xx[2] ^ yy[2];
        zz[3] = xx[3] ^ yy[3];
        zz[4] = xx[4] ^ yy[4];
        zz[5] = xx[5] ^ yy[5];
        zz[6] = xx[6] ^ yy[6];
        zz[7] = xx[7] ^ yy[7];
        zz[8] = xx[8] ^ yy[8];
    }

    public static void addOne(long[] x, long[] z)
    {
        z[0] = x[0] ^ 1L;
        z[1] = x[1];
        z[2] = x[2];
        z[3] = x[3];
        z[4] = x[4];
    }

    private static void addTo(long[] x, long[] z)
    {
        z[0] ^= x[0];
        z[1] ^= x[1];
        z[2] ^= x[2];
        z[3] ^= x[3];
        z[4] ^= x[4];
    }

    public static long[] fromBigInteger(BigInteger x)
    {
        return Nat.fromBigInteger64(283, x);
    }

    public static void halfTrace(long[] x, long[] z)
    {
        long[] tt = Nat.create64(9);

        Nat320.copy64(x, z);
        for (int i = 1; i < 283; i += 2)
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
        if (Nat320.isZero64(x))
        {
            throw new IllegalStateException();
        }

        // Itoh-Tsujii inversion

        long[] t0 = Nat320.create64();
        long[] t1 = Nat320.create64();

        square(x, t0);
        multiply(t0, x, t0);
        squareN(t0, 2, t1);
        multiply(t1, t0, t1);
        squareN(t1, 4, t0);
        multiply(t0, t1, t0);
        squareN(t0, 8, t1);
        multiply(t1, t0, t1);
        square(t1, t1);
        multiply(t1, x, t1);
        squareN(t1, 17, t0);
        multiply(t0, t1, t0);
        square(t0, t0);
        multiply(t0, x, t0);
        squareN(t0, 35, t1);
        multiply(t1, t0, t1);
        squareN(t1, 70, t0);
        multiply(t0, t1, t0);
        square(t0, t0);
        multiply(t0, x, t0);
        squareN(t0, 141, t1);
        multiply(t1, t0, t1);
        square(t1, z);
    }

    public static void multiply(long[] x, long[] y, long[] z)
    {
        long[] tt = Nat320.createExt64();
        implMultiply(x, y, tt);
        reduce(tt, z);
    }

    public static void multiplyAddToExt(long[] x, long[] y, long[] zz)
    {
        long[] tt = Nat320.createExt64();
        implMultiply(x, y, tt);
        addExt(zz, tt, zz);
    }

    public static void reduce(long[] xx, long[] z)
    {
        long x0 = xx[0], x1 = xx[1], x2 = xx[2], x3 = xx[3], x4 = xx[4];
        long x5 = xx[5], x6 = xx[6], x7 = xx[7], x8 = xx[8];

        x3 ^= (x8 <<  37) ^ (x8 <<  42) ^ (x8 <<  44) ^ (x8 <<  49);
        x4 ^= (x8 >>> 27) ^ (x8 >>> 22) ^ (x8 >>> 20) ^ (x8 >>> 15);

        x2 ^= (x7 <<  37) ^ (x7 <<  42) ^ (x7 <<  44) ^ (x7 <<  49);
        x3 ^= (x7 >>> 27) ^ (x7 >>> 22) ^ (x7 >>> 20) ^ (x7 >>> 15);

        x1 ^= (x6 <<  37) ^ (x6 <<  42) ^ (x6 <<  44) ^ (x6 <<  49);
        x2 ^= (x6 >>> 27) ^ (x6 >>> 22) ^ (x6 >>> 20) ^ (x6 >>> 15);

        x0 ^= (x5 <<  37) ^ (x5 <<  42) ^ (x5 <<  44) ^ (x5 <<  49);
        x1 ^= (x5 >>> 27) ^ (x5 >>> 22) ^ (x5 >>> 20) ^ (x5 >>> 15);

        long t = x4 >>> 27;
        z[0]   = x0 ^ t ^ (t << 5) ^ (t << 7) ^ (t << 12);
        z[1]   = x1;
        z[2]   = x2;
        z[3]   = x3;
        z[4]   = x4 & M27;
    }

    public static void reduce37(long[] z, int zOff)
    {
        long z4      = z[zOff + 4], t = z4 >>> 27;
        z[zOff    ] ^= t ^ (t << 5) ^ (t << 7) ^ (t << 12);
        z[zOff + 4]  = z4 & M27;
    }

    public static void sqrt(long[] x, long[] z)
    {
        long[] odd = Nat320.create64();

        long u0, u1;
        u0 = Interleave.unshuffle(x[0]); u1 = Interleave.unshuffle(x[1]);
        long e0 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
        odd[0]  = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

        u0 = Interleave.unshuffle(x[2]); u1 = Interleave.unshuffle(x[3]);
        long e1 = (u0 & 0x00000000FFFFFFFFL) | (u1 << 32);
        odd[1]  = (u0 >>> 32) | (u1 & 0xFFFFFFFF00000000L);

        u0 = Interleave.unshuffle(x[4]);
        long e2 = (u0 & 0x00000000FFFFFFFFL);
        odd[2]  = (u0 >>> 32);

        multiply(odd, ROOT_Z, z);

        z[0] ^= e0;
        z[1] ^= e1;
        z[2] ^= e2;
    }

    public static void square(long[] x, long[] z)
    {
        long[] tt = Nat.create64(9);
        implSquare(x, tt);
        reduce(tt, z);
    }

    public static void squareAddToExt(long[] x, long[] zz)
    {
        long[] tt = Nat.create64(9);
        implSquare(x, tt);
        addExt(zz, tt, zz);
    }

    public static void squareN(long[] x, int n, long[] z)
    {
//        assert n > 0;

        long[] tt = Nat.create64(9);
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
        // Non-zero-trace bits: 0, 271
        return (int)(x[0] ^ (x[4] >>> 15)) & 1;
    }

    protected static void implCompactExt(long[] zz)
    {
        long z0 = zz[0], z1 = zz[1], z2 = zz[2], z3 = zz[3], z4 = zz[4];
        long z5 = zz[5], z6 = zz[6], z7 = zz[7], z8 = zz[8], z9 = zz[9];
        zz[0] =  z0         ^ (z1 << 57);
        zz[1] = (z1 >>>  7) ^ (z2 << 50);
        zz[2] = (z2 >>> 14) ^ (z3 << 43);
        zz[3] = (z3 >>> 21) ^ (z4 << 36);
        zz[4] = (z4 >>> 28) ^ (z5 << 29);
        zz[5] = (z5 >>> 35) ^ (z6 << 22);
        zz[6] = (z6 >>> 42) ^ (z7 << 15);
        zz[7] = (z7 >>> 49) ^ (z8 <<  8);
        zz[8] = (z8 >>> 56) ^ (z9 <<  1);
        zz[9] = (z9 >>> 63); // Zero!
    }

    protected static void implExpand(long[] x, long[] z)
    {
        long x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3], x4 = x[4];
        z[0] = x0 & M57;
        z[1] = ((x0 >>> 57) ^ (x1 <<  7)) & M57;
        z[2] = ((x1 >>> 50) ^ (x2 << 14)) & M57;
        z[3] = ((x2 >>> 43) ^ (x3 << 21)) & M57;
        z[4] = ((x3 >>> 36) ^ (x4 << 28));
    }

//    protected static void addMs(long[] zz, int zOff, long[] p, int... ms)
//    {
//        long t0 = 0, t1 = 0;
//        for (int m : ms)
//        {
//            int i = (m - 1) << 1;
//            t0 ^= p[i    ];
//            t1 ^= p[i + 1];
//        }
//        zz[zOff    ] ^= t0;
//        zz[zOff + 1] ^= t1;
//    }

    protected static void implMultiply(long[] x, long[] y, long[] zz)
    {
        /*
         * Formula (17) from "Some New Results on Binary Polynomial Multiplication",
         * Murat Cenk and M. Anwar Hasan.
         *
         * The formula as given contained an error in the term t25, as noted below
         */
        long[] a = new long[5], b = new long[5];
        implExpand(x, a);
        implExpand(y, b);

        long[] u = zz;
        long[] p = new long[26];

        implMulw(u, a[0], b[0], p, 0);                  // m1
        implMulw(u, a[1], b[1], p, 2);                  // m2
        implMulw(u, a[2], b[2], p, 4);                  // m3
        implMulw(u, a[3], b[3], p, 6);                  // m4
        implMulw(u, a[4], b[4], p, 8);                  // m5

        long u0 = a[0] ^ a[1], v0 = b[0] ^ b[1];
        long u1 = a[0] ^ a[2], v1 = b[0] ^ b[2];
        long u2 = a[2] ^ a[4], v2 = b[2] ^ b[4];
        long u3 = a[3] ^ a[4], v3 = b[3] ^ b[4];

        implMulw(u, u1 ^ a[3], v1 ^ b[3], p, 18);       // m10
        implMulw(u, u2 ^ a[1], v2 ^ b[1], p, 20);       // m11

        long A4 = u0 ^ u3  , B4 = v0 ^ v3;
        long A5 = A4 ^ a[2], B5 = B4 ^ b[2];

        implMulw(u, A4, B4, p, 22);                     // m12
        implMulw(u, A5, B5, p, 24);                     // m13

        implMulw(u, u0, v0, p, 10);                     // m6
        implMulw(u, u1, v1, p, 12);                     // m7
        implMulw(u, u2, v2, p, 14);                     // m8
        implMulw(u, u3, v3, p, 16);                     // m9


        // Original method, corresponding to formula (16)
//        addMs(zz, 0, p, 1);
//        addMs(zz, 1, p, 1, 2, 6);
//        addMs(zz, 2, p, 1, 2, 3, 7);
//        addMs(zz, 3, p, 1, 3, 4, 5, 8, 10, 12, 13);
//        addMs(zz, 4, p, 1, 2, 4, 5, 6, 9, 10, 11, 13);
//        addMs(zz, 5, p, 1, 2, 3, 5, 7, 11, 12, 13);
//        addMs(zz, 6, p, 3, 4, 5, 8);
//        addMs(zz, 7, p, 4, 5, 9);
//        addMs(zz, 8, p, 5);

        // Improved method factors out common single-word terms
        // NOTE: p1,...,p26 in the paper maps to p[0],...,p[25] here

        zz[0]    = p[ 0];
        zz[9]    = p[ 9];

        long t1  = p[ 0] ^ p[ 1];
        long t2  = t1    ^ p[ 2];
        long t3  = t2    ^ p[10];

        zz[1]    = t3;

        long t4  = p[ 3] ^ p[ 4];
        long t5  = p[11] ^ p[12];
        long t6  = t4    ^ t5;
        long t7  = t2    ^ t6;

        zz[2]    = t7;

        long t8  = t1    ^ t4;
        long t9  = p[ 5] ^ p[ 6];
        long t10 = t8    ^ t9;
        long t11 = t10   ^ p[ 8];
        long t12 = p[13] ^ p[14];
        long t13 = t11   ^ t12;
        long t14 = p[18] ^ p[22];
        long t15 = t14   ^ p[24];
        long t16 = t13   ^ t15;

        zz[3]    = t16;

        long t17 = p[ 7] ^ p[ 8];
        long t18 = t17   ^ p[ 9];
        long t19 = t18   ^ p[17];

        zz[8]    = t19;

        long t20 = t18   ^ t9;
        long t21 = p[15] ^ p[16];
        long t22 = t20   ^ t21;

        zz[7]    = t22;

        long t23 = t22   ^ t3;
        long t24 = p[19] ^ p[20];
//      long t25 = p[23] ^ p[24];
        long t25 = p[25] ^ p[24];       // Fixes an error in the paper: p[23] -> p{25]
        long t26 = p[18] ^ p[23];
        long t27 = t24   ^ t25;
        long t28 = t27   ^ t26;
        long t29 = t28   ^ t23;

        zz[4]    = t29;

        long t30 = t7    ^ t19;
        long t31 = t27   ^ t30;
        long t32 = p[21] ^ p[22];
        long t33 = t31   ^ t32;

        zz[5]    = t33;

        long t34 = t11   ^ p[0];
        long t35 = t34   ^ p[9];
        long t36 = t35   ^ t12;
        long t37 = t36   ^ p[21];
        long t38 = t37   ^ p[23];
        long t39 = t38   ^ p[25];

        zz[6]    = t39;

        implCompactExt(zz);
    }

    protected static void implMulw(long[] u, long x, long y, long[] z, int zOff)
    {
//        assert x >>> 57 == 0;
//        assert y >>> 57 == 0;

//      u[0] = 0;
        u[1] = y;
        u[2] = u[1] << 1;
        u[3] = u[2] ^  y;
        u[4] = u[2] << 1;
        u[5] = u[4] ^  y;
        u[6] = u[3] << 1;
        u[7] = u[6] ^  y;

        int j = (int)x;
        long g, h = 0, l = u[j & 7];
        int k = 48;
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

        h ^= ((x & 0x0100804020100800L) & ((y << 7) >> 63)) >>> 8;

//        assert h >>> 49 == 0;

        z[zOff    ] = l & M57;
        z[zOff + 1] = (l >>> 57) ^ (h << 7);
    }

    protected static void implSquare(long[] x, long[] zz)
    {
        Interleave.expand64To128(x, 0, 4, zz, 0);
        zz[8] = Interleave.expand32to64((int)x[4]);
    }
}
