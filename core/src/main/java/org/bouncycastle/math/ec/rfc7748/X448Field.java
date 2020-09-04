package org.bouncycastle.math.ec.rfc7748;

import org.bouncycastle.math.raw.Mod;

public abstract class X448Field
{
    public static final int SIZE = 16;

    private static final int M28 = 0x0FFFFFFF;
    private static final long U32 = 0xFFFFFFFFL;

    private static final int[] P32 = new int[]{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };

    protected X448Field() {}

    public static void add(int[] x, int[] y, int[] z)
    {
        for (int i = 0; i < SIZE; ++i)
        {
            z[i] = x[i] + y[i];
        }
    }

    public static void addOne(int[] z)
    {
        z[0] += 1;
    }

    public static void addOne(int[] z, int zOff)
    {
        z[zOff] += 1;
    }

//    public static void apm(int[] x, int[] y, int[] zp, int[] zm)
//    {
//        for (int i = 0; i < SIZE; ++i)
//        {
//            int xi = x[i], yi = y[i];
//            zp[i] = xi + yi;
//            zm[i] = xi - yi;
//        }
//    }

    public static void carry(int[] z)
    {
        int z0 = z[0], z1 = z[1], z2 = z[2], z3 = z[3], z4 = z[4], z5 = z[5], z6 = z[6], z7 = z[7];
        int z8 = z[8], z9 = z[9], z10 = z[10], z11 = z[11], z12 = z[12], z13 = z[13], z14 = z[14], z15 = z[15];

        z1   += (z0 >>> 28); z0 &= M28;
        z5   += (z4 >>> 28); z4 &= M28;
        z9   += (z8 >>> 28); z8 &= M28;
        z13  += (z12 >>> 28); z12 &= M28;

        z2   += (z1 >>> 28); z1 &= M28;
        z6   += (z5 >>> 28); z5 &= M28;
        z10  += (z9 >>> 28); z9 &= M28;
        z14  += (z13 >>> 28); z13 &= M28;

        z3   += (z2 >>> 28); z2 &= M28;
        z7   += (z6 >>> 28); z6 &= M28;
        z11  += (z10 >>> 28); z10 &= M28;
        z15  += (z14 >>> 28); z14 &= M28;

        int t = z15 >>> 28; z15 &= M28;
        z0   += t;
        z8   += t;

        z4   += (z3 >>> 28); z3 &= M28;
        z8   += (z7 >>> 28); z7 &= M28;
        z12  += (z11 >>> 28); z11 &= M28;

        z1   += (z0 >>> 28); z0 &= M28;
        z5   += (z4 >>> 28); z4 &= M28;
        z9   += (z8 >>> 28); z8 &= M28;
        z13  += (z12 >>> 28); z12 &= M28;
        
        z[0] = z0; z[1] = z1; z[2] = z2; z[3] = z3; z[4] = z4; z[5] = z5; z[6] = z6; z[7] = z7;
        z[8] = z8; z[9] = z9; z[10] = z10; z[11] = z11; z[12] = z12; z[13] = z13; z[14] = z14; z[15] = z15;
    }

    public static void cmov(int cond, int[] x, int xOff, int[] z, int zOff)
    {
//        assert 0 == cond || -1 == cond;

        for (int i = 0; i < SIZE; ++i)
        {
            int z_i = z[zOff + i], diff = z_i ^ x[xOff + i];
            z_i ^= (diff & cond);
            z[zOff + i] = z_i;
        }
    }

    public static void cnegate(int negate, int[] z)
    {
//        assert negate >>> 1 == 0;

        int[] t = create();
        sub(t, z, t);

        cmov(-negate, t, 0, z, 0);
    }

    public static void copy(int[] x, int xOff, int[] z, int zOff)
    {
        for (int i = 0; i < SIZE; ++i)
        {
            z[zOff + i] = x[xOff + i];
        }
    }

    public static int[] create()
    {
        return new int[SIZE];
    }

    public static int[] createTable(int n)
    {
        return new int[SIZE * n];
    }

    public static void cswap(int swap, int[] a, int[] b)
    {
//        assert swap >>> 1 == 0;
//        assert a != b;

        int mask = 0 - swap;
        for (int i = 0; i < SIZE; ++i)
        {
            int ai = a[i], bi = b[i];
            int dummy = mask & (ai ^ bi);
            a[i] = ai ^ dummy; 
            b[i] = bi ^ dummy; 
        }
    }

    public static void decode(int[] x, int xOff, int[] z)
    {
        decode224(x, xOff, z, 0);
        decode224(x, xOff + 7, z, 8);
    }

    public static void decode(byte[] x, int xOff, int[] z)
    {
        decode56(x, xOff, z, 0);
        decode56(x, xOff + 7, z, 2);
        decode56(x, xOff + 14, z, 4);
        decode56(x, xOff + 21, z, 6);
        decode56(x, xOff + 28, z, 8);
        decode56(x, xOff + 35, z, 10);
        decode56(x, xOff + 42, z, 12);
        decode56(x, xOff + 49, z, 14);
    }

    private static void decode224(int[] x, int xOff, int[] z, int zOff)
    {
        int x0 = x[xOff + 0], x1 = x[xOff + 1], x2 = x[xOff + 2], x3 = x[xOff + 3];
        int x4 = x[xOff + 4], x5 = x[xOff + 5], x6 = x[xOff + 6];

        z[zOff + 0] =  x0                    & M28;
        z[zOff + 1] = (x0 >>> 28 | x1 <<  4) & M28;
        z[zOff + 2] = (x1 >>> 24 | x2 <<  8) & M28;
        z[zOff + 3] = (x2 >>> 20 | x3 << 12) & M28;
        z[zOff + 4] = (x3 >>> 16 | x4 << 16) & M28;
        z[zOff + 5] = (x4 >>> 12 | x5 << 20) & M28;
        z[zOff + 6] = (x5 >>>  8 | x6 << 24) & M28;
        z[zOff + 7] =  x6 >>>  4;
    }

    private static int decode24(byte[] bs, int off)
    {
        int n = bs[  off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF) << 16;
        return n;
    }

    private static int decode32(byte[] bs, int off)
    {
        int n = bs[  off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    private static void decode56(byte[] bs, int off, int[] z, int zOff)
    {
        int lo = decode32(bs, off);
        int hi = decode24(bs, off + 4);
        z[zOff] = lo & M28;
        z[zOff + 1] = (lo >>> 28) | (hi << 4);
    }

    public static void encode(int[] x, int[] z, int zOff)
    {
        encode224(x, 0, z, zOff);
        encode224(x, 8, z, zOff + 7);
    }

    public static void encode(int[] x,  byte[] z , int zOff)
    {
        encode56(x, 0, z, zOff);
        encode56(x, 2, z, zOff + 7);
        encode56(x, 4, z, zOff + 14);
        encode56(x, 6, z, zOff + 21);
        encode56(x, 8, z, zOff + 28);
        encode56(x, 10, z, zOff + 35);
        encode56(x, 12, z, zOff + 42);
        encode56(x, 14, z, zOff + 49);
    }

    private static void encode224(int[] x, int xOff, int[] is, int off)
    {
        int x0 = x[xOff + 0], x1 = x[xOff + 1], x2 = x[xOff + 2], x3 = x[xOff + 3];
        int x4 = x[xOff + 4], x5 = x[xOff + 5], x6 = x[xOff + 6], x7 = x[xOff + 7];

        is[off + 0] =  x0         | (x1 << 28);
        is[off + 1] = (x1 >>>  4) | (x2 << 24);
        is[off + 2] = (x2 >>>  8) | (x3 << 20);
        is[off + 3] = (x3 >>> 12) | (x4 << 16);
        is[off + 4] = (x4 >>> 16) | (x5 << 12);
        is[off + 5] = (x5 >>> 20) | (x6 <<  8);
        is[off + 6] = (x6 >>> 24) | (x7 <<  4);
    }

    private static void encode24(int n, byte[] bs, int off)
    {
        bs[  off] = (byte)(n       );
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
    }

    private static void encode32(int n, byte[] bs, int off)
    {
        bs[  off] = (byte)(n       );
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    private static void encode56(int[] x, int xOff, byte[] bs, int off)
    {
        int lo = x[xOff], hi = x[xOff + 1];
        encode32(lo | (hi << 28), bs, off);
        encode24(hi >>> 4, bs, off + 4);
    }

    public static void inv(int[] x, int[] z)
    {
//        int[] t = create();
//        powPm3d4(x, t);
//        sqr(t, 2, t);
//        mul(t, x, z);

        int[] t = create();
        int[] u = new int[14];

        copy(x, 0, t, 0);
        normalize(t);
        encode(t, u, 0);

        Mod.modOddInverse(P32, u, u);

        decode(u, 0, z);
    }

    public static void invVar(int[] x, int[] z)
    {
        int[] t = create();
        int[] u = new int[14];

        copy(x, 0, t, 0);
        normalize(t);
        encode(t, u, 0);

        Mod.modOddInverseVar(P32, u, u);

        decode(u, 0, z);
    }

    public static int isZero(int[] x)
    {
        int d = 0;
        for (int i = 0; i < SIZE; ++i)
        {
            d |= x[i];
        }
        d = (d >>> 1) | (d & 1);
        return (d - 1) >> 31;
    }

    public static boolean isZeroVar(int[] x)
    {
        return 0 != isZero(x);
    }

    public static void mul(int[] x, int y, int[] z)
    {
        int x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3], x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
        int x8 = x[8], x9 = x[9], x10 = x[10], x11 = x[11], x12 = x[12], x13 = x[13], x14 = x[14], x15 = x[15];

        int z1, z5, z9, z13;
        long c, d, e, f;

        c     = (long)x1 * y;
        z1    = (int)c & M28; c >>>= 28;
        d     = (long)x5 * y;
        z5    = (int)d & M28; d >>>= 28;
        e     = (long)x9 * y;
        z9    = (int)e & M28; e >>>= 28;
        f     = (long)x13 * y;
        z13   = (int)f & M28; f >>>= 28;

        c    += (long)x2 * y;
        z[2]  = (int)c & M28; c >>>= 28;
        d    += (long)x6 * y;
        z[6]  = (int)d & M28; d >>>= 28;
        e    += (long)x10 * y;
        z[10] = (int)e & M28; e >>>= 28;
        f    += (long)x14 * y;
        z[14] = (int)f & M28; f >>>= 28;

        c    += (long)x3 * y;
        z[3]  = (int)c & M28; c >>>= 28;
        d    += (long)x7 * y;
        z[7]  = (int)d & M28; d >>>= 28;
        e    += (long)x11 * y;
        z[11] = (int)e & M28; e >>>= 28;
        f    += (long)x15 * y;
        z[15] = (int)f & M28; f >>>= 28;

        d    += f;

        c    += (long)x4 * y;
        z[4]  = (int)c & M28; c >>>= 28;
        d    += (long)x8 * y;
        z[8]  = (int)d & M28; d >>>= 28;
        e    += (long)x12 * y;
        z[12] = (int)e & M28; e >>>= 28;
        f    += (long)x0 * y;
        z[0]  = (int)f & M28; f >>>= 28;

        z[1]  = z1 + (int)f;
        z[5]  = z5 + (int)c;
        z[9]  = z9 + (int)d;
        z[13] = z13 + (int)e;
    }

    public static void mul(int[] x, int[] y, int[] z)
    {
        int x0 = x[0];
        int x1 = x[1];
        int x2 = x[2];
        int x3 = x[3];
        int x4 = x[4];
        int x5 = x[5];
        int x6 = x[6];
        int x7 = x[7];

        int u0 = x[8];
        int u1 = x[9];
        int u2 = x[10];
        int u3 = x[11];
        int u4 = x[12];
        int u5 = x[13];
        int u6 = x[14];
        int u7 = x[15];

        int y0 = y[0];
        int y1 = y[1];
        int y2 = y[2];
        int y3 = y[3];
        int y4 = y[4];
        int y5 = y[5];
        int y6 = y[6];
        int y7 = y[7];

        int v0 = y[8];
        int v1 = y[9];
        int v2 = y[10];
        int v3 = y[11];
        int v4 = y[12];
        int v5 = y[13];
        int v6 = y[14];
        int v7 = y[15];

        int s0 = x0 + u0;
        int s1 = x1 + u1;
        int s2 = x2 + u2;
        int s3 = x3 + u3;
        int s4 = x4 + u4;
        int s5 = x5 + u5;
        int s6 = x6 + u6;
        int s7 = x7 + u7;

        int t0 = y0 + v0;
        int t1 = y1 + v1;
        int t2 = y2 + v2;
        int t3 = y3 + v3;
        int t4 = y4 + v4;
        int t5 = y5 + v5;
        int t6 = y6 + v6;
        int t7 = y7 + v7;

        int z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15;
        long c, d;

        long f0  = (long)x0 * y0;
        long f8  = (long)x7 * y1
                 + (long)x6 * y2
                 + (long)x5 * y3
                 + (long)x4 * y4
                 + (long)x3 * y5
                 + (long)x2 * y6
                 + (long)x1 * y7;
        long g0  = (long)u0 * v0;
        long g8  = (long)u7 * v1
                 + (long)u6 * v2
                 + (long)u5 * v3
                 + (long)u4 * v4
                 + (long)u3 * v5
                 + (long)u2 * v6
                 + (long)u1 * v7;
        long h0  = (long)s0 * t0;
        long h8  = (long)s7 * t1
                 + (long)s6 * t2
                 + (long)s5 * t3
                 + (long)s4 * t4
                 + (long)s3 * t5
                 + (long)s2 * t6
                 + (long)s1 * t7;

        c        = f0 + g0 + h8 - f8;
        z0       = (int)c & M28; c >>>= 28;
        d        = g8 + h0 - f0 + h8;
        z8       = (int)d & M28; d >>>= 28;

        long f1  = (long)x1 * y0
                 + (long)x0 * y1;
        long f9  = (long)x7 * y2
                 + (long)x6 * y3
                 + (long)x5 * y4
                 + (long)x4 * y5
                 + (long)x3 * y6
                 + (long)x2 * y7;
        long g1  = (long)u1 * v0
                 + (long)u0 * v1;
        long g9  = (long)u7 * v2
                 + (long)u6 * v3
                 + (long)u5 * v4
                 + (long)u4 * v5
                 + (long)u3 * v6
                 + (long)u2 * v7;
        long h1  = (long)s1 * t0
                 + (long)s0 * t1;
        long h9  = (long)s7 * t2
                 + (long)s6 * t3
                 + (long)s5 * t4
                 + (long)s4 * t5
                 + (long)s3 * t6
                 + (long)s2 * t7;

        c       += f1 + g1 + h9 - f9;
        z1       = (int)c & M28; c >>>= 28;
        d       += g9 + h1 - f1 + h9;
        z9       = (int)d & M28; d >>>= 28;

        long f2  = (long)x2 * y0
                 + (long)x1 * y1
                 + (long)x0 * y2;
        long f10 = (long)x7 * y3
                 + (long)x6 * y4
                 + (long)x5 * y5
                 + (long)x4 * y6
                 + (long)x3 * y7;
        long g2  = (long)u2 * v0
                 + (long)u1 * v1
                 + (long)u0 * v2;
        long g10 = (long)u7 * v3
                 + (long)u6 * v4
                 + (long)u5 * v5
                 + (long)u4 * v6
                 + (long)u3 * v7;
        long h2  = (long)s2 * t0
                 + (long)s1 * t1
                 + (long)s0 * t2;
        long h10 = (long)s7 * t3
                 + (long)s6 * t4
                 + (long)s5 * t5
                 + (long)s4 * t6
                 + (long)s3 * t7;

        c       += f2 + g2 + h10 - f10;
        z2       = (int)c & M28; c >>>= 28;
        d       += g10 + h2 - f2 + h10;
        z10      = (int)d & M28; d >>>= 28;

        long f3  = (long)x3 * y0
                 + (long)x2 * y1
                 + (long)x1 * y2
                 + (long)x0 * y3;
        long f11 = (long)x7 * y4
                 + (long)x6 * y5
                 + (long)x5 * y6
                 + (long)x4 * y7;
        long g3  = (long)u3 * v0
                 + (long)u2 * v1
                 + (long)u1 * v2
                 + (long)u0 * v3;
        long g11 = (long)u7 * v4
                 + (long)u6 * v5
                 + (long)u5 * v6
                 + (long)u4 * v7;
        long h3  = (long)s3 * t0
                 + (long)s2 * t1
                 + (long)s1 * t2
                 + (long)s0 * t3;
        long h11 = (long)s7 * t4
                 + (long)s6 * t5
                 + (long)s5 * t6
                 + (long)s4 * t7;

        c       += f3 + g3 + h11 - f11;
        z3       = (int)c & M28; c >>>= 28;
        d       += g11 + h3 - f3 + h11;
        z11      = (int)d & M28; d >>>= 28;

        long f4  = (long)x4 * y0
                 + (long)x3 * y1
                 + (long)x2 * y2
                 + (long)x1 * y3
                 + (long)x0 * y4;
        long f12 = (long)x7 * y5
                 + (long)x6 * y6
                 + (long)x5 * y7;
        long g4  = (long)u4 * v0
                 + (long)u3 * v1
                 + (long)u2 * v2
                 + (long)u1 * v3
                 + (long)u0 * v4;
        long g12 = (long)u7 * v5
                 + (long)u6 * v6
                 + (long)u5 * v7;
        long h4  = (long)s4 * t0
                 + (long)s3 * t1
                 + (long)s2 * t2
                 + (long)s1 * t3
                 + (long)s0 * t4;
        long h12 = (long)s7 * t5
                 + (long)s6 * t6
                 + (long)s5 * t7;

        c       += f4 + g4 + h12 - f12;
        z4       = (int)c & M28; c >>>= 28;
        d       += g12 + h4 - f4 + h12;
        z12      = (int)d & M28; d >>>= 28;

        long f5  = (long)x5 * y0
                 + (long)x4 * y1
                 + (long)x3 * y2
                 + (long)x2 * y3
                 + (long)x1 * y4
                 + (long)x0 * y5;
        long f13 = (long)x7 * y6
                 + (long)x6 * y7;
        long g5  = (long)u5 * v0
                 + (long)u4 * v1
                 + (long)u3 * v2
                 + (long)u2 * v3
                 + (long)u1 * v4
                 + (long)u0 * v5;
        long g13 = (long)u7 * v6
                 + (long)u6 * v7;
        long h5  = (long)s5 * t0
                 + (long)s4 * t1
                 + (long)s3 * t2
                 + (long)s2 * t3
                 + (long)s1 * t4
                 + (long)s0 * t5;
        long h13 = (long)s7 * t6
                 + (long)s6 * t7;

        c       += f5 + g5 + h13 - f13;
        z5       = (int)c & M28; c >>>= 28;
        d       += g13 + h5 - f5 + h13;
        z13      = (int)d & M28; d >>>= 28;

        long f6  = (long)x6 * y0
                 + (long)x5 * y1
                 + (long)x4 * y2
                 + (long)x3 * y3
                 + (long)x2 * y4
                 + (long)x1 * y5
                 + (long)x0 * y6;
        long f14 = (long)x7 * y7;
        long g6  = (long)u6 * v0
                 + (long)u5 * v1
                 + (long)u4 * v2
                 + (long)u3 * v3
                 + (long)u2 * v4
                 + (long)u1 * v5
                 + (long)u0 * v6;
        long g14 = (long)u7 * v7;
        long h6  = (long)s6 * t0
                 + (long)s5 * t1
                 + (long)s4 * t2
                 + (long)s3 * t3
                 + (long)s2 * t4
                 + (long)s1 * t5
                 + (long)s0 * t6;
        long h14 = (long)s7 * t7;

        c       += f6 + g6 + h14 - f14;
        z6       = (int)c & M28; c >>>= 28;
        d       += g14 + h6 - f6 + h14;
        z14      = (int)d & M28; d >>>= 28;

        long f7  = (long)x7 * y0
                 + (long)x6 * y1
                 + (long)x5 * y2
                 + (long)x4 * y3
                 + (long)x3 * y4
                 + (long)x2 * y5
                 + (long)x1 * y6
                 + (long)x0 * y7;
        long g7  = (long)u7 * v0
                 + (long)u6 * v1
                 + (long)u5 * v2
                 + (long)u4 * v3
                 + (long)u3 * v4
                 + (long)u2 * v5
                 + (long)u1 * v6
                 + (long)u0 * v7;
        long h7  = (long)s7 * t0
                 + (long)s6 * t1
                 + (long)s5 * t2
                 + (long)s4 * t3
                 + (long)s3 * t4
                 + (long)s2 * t5
                 + (long)s1 * t6
                 + (long)s0 * t7;

        c       += f7 + g7;
        z7       = (int)c & M28; c >>>= 28;
        d       += h7 - f7;
        z15      = (int)d & M28; d >>>= 28;

        c       += d;

        c       += z8;
        z8       = (int)c & M28; c >>>= 28;
        d       += z0;
        z0       = (int)d & M28; d >>>= 28;
        z9      += (int)c;
        z1      += (int)d;

        z[0] = z0;
        z[1] = z1;
        z[2] = z2;
        z[3] = z3;
        z[4] = z4;
        z[5] = z5;
        z[6] = z6;
        z[7] = z7;
        z[8] = z8;
        z[9] = z9;
        z[10] = z10;
        z[11] = z11;
        z[12] = z12;
        z[13] = z13;
        z[14] = z14;
        z[15] = z15;
    }

    public static void negate(int[] x, int[] z)
    {
        int[] zero = create();
        sub(zero, x, z);
    }

    public static void normalize(int[] z)
    {
//        int x = ((z[15] >>> (28 - 1)) & 1);
        reduce(z, 1);
        reduce(z, -1);
//        assert z[15] >>> 28 == 0;
    }

    public static void one(int[] z)
    {
        z[0] = 1;
        for (int i = 1; i < SIZE; ++i)
        {
            z[i] = 0;
        }
    }

    private static void powPm3d4(int[] x, int[] z)
    {
        // z = x^((p-3)/4) = x^(2^446 - 2^222 - 1)
        // (223 1s) (1 0s) (222 1s)
        // Addition chain: 1 2 3 6 9 18 19 37 74 111 [222] [223]
        int[] x2 = create();    sqr(x, x2);             mul(x, x2, x2);
        int[] x3 = create();    sqr(x2, x3);            mul(x, x3, x3);
        int[] x6 = create();    sqr(x3, 3, x6);         mul(x3, x6, x6);
        int[] x9 = create();    sqr(x6, 3, x9);         mul(x3, x9, x9);
        int[] x18 = create();   sqr(x9, 9, x18);        mul(x9, x18, x18);
        int[] x19 = create();   sqr(x18, x19);          mul(x, x19, x19);
        int[] x37 = create();   sqr(x19, 18, x37);      mul(x18, x37, x37);
        int[] x74 = create();   sqr(x37, 37, x74);      mul(x37, x74, x74);
        int[] x111 = create();  sqr(x74, 37, x111);     mul(x37, x111, x111);
        int[] x222 = create();  sqr(x111, 111, x222);   mul(x111, x222, x222);
        int[] x223 = create();  sqr(x222, x223);        mul(x, x223, x223);

        int[] t = create();
        sqr(x223, 223, t);
        mul(t, x222, z);
    }

    private static void reduce(int[] z, int x)
    {
        int t = z[15], z15 = t & M28;
        t = (t >>> 28) + x;

        long cc = t;
        for (int i = 0; i < 8; ++i)
        {
            cc += z[i] & U32; z[i] = (int)cc & M28; cc >>= 28;
        }
        cc += t;
        for (int i = 8; i < 15; ++i)
        {
            cc += z[i] & U32; z[i] = (int)cc & M28; cc >>= 28;
        }
        z[15] = z15 + (int)cc;
    }

    public static void sqr(int[] x, int[] z)
    {
        int x0 = x[0];
        int x1 = x[1];
        int x2 = x[2];
        int x3 = x[3];
        int x4 = x[4];
        int x5 = x[5];
        int x6 = x[6];
        int x7 = x[7];

        int u0 = x[8];
        int u1 = x[9];
        int u2 = x[10];
        int u3 = x[11];
        int u4 = x[12];
        int u5 = x[13];
        int u6 = x[14];
        int u7 = x[15];

        int x0_2 = x0 * 2;
        int x1_2 = x1 * 2;
        int x2_2 = x2 * 2;
        int x3_2 = x3 * 2;
        int x4_2 = x4 * 2;
        int x5_2 = x5 * 2;
        int x6_2 = x6 * 2;

        int u0_2 = u0 * 2;
        int u1_2 = u1 * 2;
        int u2_2 = u2 * 2;
        int u3_2 = u3 * 2;
        int u4_2 = u4 * 2;
        int u5_2 = u5 * 2;
        int u6_2 = u6 * 2;

        int s0 = x0 + u0;
        int s1 = x1 + u1;
        int s2 = x2 + u2;
        int s3 = x3 + u3;
        int s4 = x4 + u4;
        int s5 = x5 + u5;
        int s6 = x6 + u6;
        int s7 = x7 + u7;

        /*
         * NOTE: Currently s1_2 and/or s5_2 might reach 0x80000000 (because our carry chains land at
         * x[1], x[5], x[9], x[13]). So extra care is needed to ensure they are treated as unsigned
         * multiplicands below. To avoid depending on the precise carry chains, we assume this
         * affects all the s?_2 variables.
         */
        int s0_2 = s0 * 2;
        int s1_2 = s1 * 2;
        int s2_2 = s2 * 2;
        int s3_2 = s3 * 2;
        int s4_2 = s4 * 2;
        int s5_2 = s5 * 2;
        int s6_2 = s6 * 2;

        int z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15;
        long c, d;

        long f0  = (long)x0 * x0;
        long f8  = (long)x7 * x1_2
                 + (long)x6 * x2_2
                 + (long)x5 * x3_2
                 + (long)x4 * x4;
        long g0  = (long)u0 * u0;
        long g8  = (long)u7 * u1_2
                 + (long)u6 * u2_2
                 + (long)u5 * u3_2
                 + (long)u4 * u4;
        long h0  = (long)s0 * s0;
        long h8  = (long)s7 * (s1_2 & U32)
                 + (long)s6 * (s2_2 & U32)
                 + (long)s5 * (s3_2 & U32)
                 + (long)s4 * s4;

        c        = f0 + g0 + h8 - f8;
        z0       = (int)c & M28; c >>>= 28;
        d        = g8 + h0 - f0 + h8;
        z8       = (int)d & M28; d >>>= 28;

        long f1  = (long)x1 * x0_2;
        long f9  = (long)x7 * x2_2
                 + (long)x6 * x3_2
                 + (long)x5 * x4_2;
        long g1  = (long)u1 * u0_2;
        long g9  = (long)u7 * u2_2
                 + (long)u6 * u3_2
                 + (long)u5 * u4_2;
        long h1  = (long)s1 * (s0_2 & U32);
        long h9  = (long)s7 * (s2_2 & U32)
                 + (long)s6 * (s3_2 & U32)
                 + (long)s5 * (s4_2 & U32);

        c       += f1 + g1 + h9 - f9;
        z1       = (int)c & M28; c >>>= 28;
        d       += g9 + h1 - f1 + h9;
        z9       = (int)d & M28; d >>>= 28;

        long f2  = (long)x2 * x0_2
                 + (long)x1 * x1;
        long f10 = (long)x7 * x3_2
                 + (long)x6 * x4_2
                 + (long)x5 * x5;
        long g2  = (long)u2 * u0_2
                 + (long)u1 * u1;
        long g10 = (long)u7 * u3_2
                 + (long)u6 * u4_2
                 + (long)u5 * u5;
        long h2  = (long)s2 * (s0_2 & U32)
                 + (long)s1 * s1;
        long h10 = (long)s7 * (s3_2 & U32)
                 + (long)s6 * (s4_2 & U32)
                 + (long)s5 * s5;

        c       += f2 + g2 + h10 - f10;
        z2       = (int)c & M28; c >>>= 28;
        d       += g10 + h2 - f2 + h10;
        z10      = (int)d & M28; d >>>= 28;

        long f3  = (long)x3 * x0_2
                 + (long)x2 * x1_2;
        long f11 = (long)x7 * x4_2
                 + (long)x6 * x5_2;
        long g3  = (long)u3 * u0_2
                 + (long)u2 * u1_2;
        long g11 = (long)u7 * u4_2
                 + (long)u6 * u5_2;
        long h3  = (long)s3 * (s0_2 & U32)
                 + (long)s2 * (s1_2 & U32);
        long h11 = (long)s7 * (s4_2 & U32)
                 + (long)s6 * (s5_2 & U32);

        c       += f3 + g3 + h11 - f11;
        z3       = (int)c & M28; c >>>= 28;
        d       += g11 + h3 - f3 + h11;
        z11      = (int)d & M28; d >>>= 28;

        long f4  = (long)x4 * x0_2
                 + (long)x3 * x1_2
                 + (long)x2 * x2;
        long f12 = (long)x7 * x5_2
                 + (long)x6 * x6;
        long g4  = (long)u4 * u0_2
                 + (long)u3 * u1_2
                 + (long)u2 * u2;
        long g12 = (long)u7 * u5_2
                 + (long)u6 * u6;
        long h4  = (long)s4 * (s0_2 & U32)
                 + (long)s3 * (s1_2 & U32)
                 + (long)s2 * s2;
        long h12 = (long)s7 * (s5_2 & U32)
                 + (long)s6 * s6;

        c       += f4 + g4 + h12 - f12;
        z4       = (int)c & M28; c >>>= 28;
        d       += g12 + h4 - f4 + h12;
        z12      = (int)d & M28; d >>>= 28;

        long f5  = (long)x5 * x0_2
                 + (long)x4 * x1_2
                 + (long)x3 * x2_2;
        long f13 = (long)x7 * x6_2;
        long g5  = (long)u5 * u0_2
                 + (long)u4 * u1_2
                 + (long)u3 * u2_2;
        long g13 = (long)u7 * u6_2;
        long h5  = (long)s5 * (s0_2 & U32)
                 + (long)s4 * (s1_2 & U32)
                 + (long)s3 * (s2_2 & U32);
        long h13 = (long)s7 * (s6_2 & U32);

        c       += f5 + g5 + h13 - f13;
        z5       = (int)c & M28; c >>>= 28;
        d       += g13 + h5 - f5 + h13;
        z13      = (int)d & M28; d >>>= 28;

        long f6  = (long)x6 * x0_2
                 + (long)x5 * x1_2
                 + (long)x4 * x2_2
                 + (long)x3 * x3;
        long f14 = (long)x7 * x7;
        long g6  = (long)u6 * u0_2
                 + (long)u5 * u1_2
                 + (long)u4 * u2_2
                 + (long)u3 * u3;
        long g14 = (long)u7 * u7;
        long h6  = (long)s6 * (s0_2 & U32)
                 + (long)s5 * (s1_2 & U32)
                 + (long)s4 * (s2_2 & U32)
                 + (long)s3 * s3;
        long h14 = (long)s7 * s7;

        c       += f6 + g6 + h14 - f14;
        z6       = (int)c & M28; c >>>= 28;
        d       += g14 + h6 - f6 + h14;
        z14      = (int)d & M28; d >>>= 28;

        long f7  = (long)x7 * x0_2
                 + (long)x6 * x1_2
                 + (long)x5 * x2_2
                 + (long)x4 * x3_2;
        long g7  = (long)u7 * u0_2
                 + (long)u6 * u1_2
                 + (long)u5 * u2_2
                 + (long)u4 * u3_2;
        long h7  = (long)s7 * (s0_2 & U32)
                 + (long)s6 * (s1_2 & U32)
                 + (long)s5 * (s2_2 & U32)
                 + (long)s4 * (s3_2 & U32);

        c       += f7 + g7;
        z7       = (int)c & M28; c >>>= 28;
        d       += h7 - f7;
        z15      = (int)d & M28; d >>>= 28;

        c       += d;

        c       += z8;
        z8       = (int)c & M28; c >>>= 28;
        d       += z0;
        z0       = (int)d & M28; d >>>= 28;
        z9      += (int)c;
        z1      += (int)d;

        z[0] = z0;
        z[1] = z1;
        z[2] = z2;
        z[3] = z3;
        z[4] = z4;
        z[5] = z5;
        z[6] = z6;
        z[7] = z7;
        z[8] = z8;
        z[9] = z9;
        z[10] = z10;
        z[11] = z11;
        z[12] = z12;
        z[13] = z13;
        z[14] = z14;
        z[15] = z15;
    }

    public static void sqr(int[] x, int n, int[] z)
    {
//        assert n > 0;

        sqr(x, z);

        while (--n > 0)
        {
            sqr(z, z);
        }
    }

    public static boolean sqrtRatioVar(int[] u, int[] v, int[] z)
    {
        int[] u3v = create();
        int[] u5v3 = create();

        sqr(u, u3v);
        mul(u3v, v, u3v);
        sqr(u3v, u5v3);
        mul(u3v, u, u3v);
        mul(u5v3, u, u5v3);
        mul(u5v3, v, u5v3);

        int[] x = create();
        powPm3d4(u5v3, x);
        mul(x, u3v, x);

        int[] t = create();
        sqr(x, t);
        mul(t, v, t);

        sub(u, t, t);
        normalize(t);

        if (isZeroVar(t))
        {
            copy(x, 0, z, 0);
            return true;
        }

        return false;
    }

    public static void sub(int[] x, int[] y, int[] z)
    {
        int x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3], x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
        int x8 = x[8], x9 = x[9], x10 = x[10], x11 = x[11], x12 = x[12], x13 = x[13], x14 = x[14], x15 = x[15];
        int y0 = y[0], y1 = y[1], y2 = y[2], y3 = y[3], y4 = y[4], y5 = y[5], y6 = y[6], y7 = y[7];
        int y8 = y[8], y9 = y[9], y10 = y[10], y11 = y[11], y12 = y[12], y13 = y[13], y14 = y[14], y15 = y[15];

        int z0 = x0 + 0x1FFFFFFE - y0;
        int z1 = x1 + 0x1FFFFFFE - y1;
        int z2 = x2 + 0x1FFFFFFE - y2;
        int z3 = x3 + 0x1FFFFFFE - y3;
        int z4 = x4 + 0x1FFFFFFE - y4;
        int z5 = x5 + 0x1FFFFFFE - y5;
        int z6 = x6 + 0x1FFFFFFE - y6;
        int z7 = x7 + 0x1FFFFFFE - y7;
        int z8 = x8 + 0x1FFFFFFC - y8;
        int z9 = x9 + 0x1FFFFFFE - y9;
        int z10 = x10 + 0x1FFFFFFE - y10;
        int z11 = x11 + 0x1FFFFFFE - y11;
        int z12 = x12 + 0x1FFFFFFE - y12;
        int z13 = x13 + 0x1FFFFFFE - y13;
        int z14 = x14 + 0x1FFFFFFE - y14;
        int z15 = x15 + 0x1FFFFFFE - y15;

        z2   += z1 >>> 28; z1 &= M28;
        z6   += z5 >>> 28; z5 &= M28;
        z10  += z9 >>> 28; z9 &= M28;
        z14  += z13 >>> 28; z13 &= M28;

        z3   += z2 >>> 28; z2 &= M28;
        z7   += z6 >>> 28; z6 &= M28;
        z11  += z10 >>> 28; z10 &= M28;
        z15  += z14 >>> 28; z14 &= M28;

        int t = z15 >>> 28; z15 &= M28;
        z0   += t;
        z8   += t;

        z4   += z3 >>> 28; z3 &= M28;
        z8   += z7 >>> 28; z7 &= M28;
        z12  += z11 >>> 28; z11 &= M28;

        z1   += z0 >>> 28; z0 &= M28;
        z5   += z4 >>> 28; z4 &= M28;
        z9   += z8 >>> 28; z8 &= M28;
        z13  += z12 >>> 28; z12 &= M28;

        z[0] = z0;
        z[1] = z1;
        z[2] = z2;
        z[3] = z3;
        z[4] = z4;
        z[5] = z5;
        z[6] = z6;
        z[7] = z7;
        z[8] = z8;
        z[9] = z9;
        z[10] = z10;
        z[11] = z11;
        z[12] = z12;
        z[13] = z13;
        z[14] = z14;
        z[15] = z15;
    }

    public static void subOne(int[] z)
    {
        int[] one = create();
        one[0] = 1;

        sub(z, one, z);
    }

    public static void zero(int[] z)
    {
        for (int i = 0; i < SIZE; ++i)
        {
            z[i] = 0;
        }
    }
}
