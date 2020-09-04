package org.bouncycastle.math.ec.rfc7748;

import org.bouncycastle.math.raw.Mod;

public abstract class X25519Field
{
    public static final int SIZE = 10;

    private static final int M24 = 0x00FFFFFF;
    private static final int M25 = 0x01FFFFFF;
    private static final int M26 = 0x03FFFFFF;

    private static final int[] P32 = new int[]{ 0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0x7FFFFFFF };
    private static final int[] ROOT_NEG_ONE = new int[]{ 0x020EA0B0, 0x0386C9D2, 0x00478C4E, 0x0035697F, 0x005E8630,
        0x01FBD7A7, 0x0340264F, 0x01F0B2B4, 0x00027E0E, 0x00570649 };

    protected X25519Field() {}

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

    public static void apm(int[] x, int[] y, int[] zp, int[] zm)
    {
        for (int i = 0; i < SIZE; ++i)
        {
            int xi = x[i], yi = y[i];
            zp[i] = xi + yi;
            zm[i] = xi - yi;
        }
    }

    public static void carry(int[] z)
    {
        int z0 = z[0], z1 = z[1], z2 = z[2], z3 = z[3], z4 = z[4];
        int z5 = z[5], z6 = z[6], z7 = z[7], z8 = z[8], z9 = z[9];

        z2 += (z1 >> 26); z1 &= M26;
        z4 += (z3 >> 26); z3 &= M26;
        z7 += (z6 >> 26); z6 &= M26;
        z9 += (z8 >> 26); z8 &= M26;

        z3 += (z2 >> 25); z2 &= M25;
        z5 += (z4 >> 25); z4 &= M25;
        z8 += (z7 >> 25); z7 &= M25;
//        z0 += (z9 >> 24) * 19; z9 &= M24;
        z0 += (z9 >> 25) * 38; z9 &= M25;

        z1 += (z0 >> 26); z0 &= M26;
        z6 += (z5 >> 26); z5 &= M26;

        z2 += (z1 >> 26); z1 &= M26;
        z4 += (z3 >> 26); z3 &= M26;
        z7 += (z6 >> 26); z6 &= M26;
        z9 += (z8 >> 26); z8 &= M26;

        z[0] = z0; z[1] = z1; z[2] = z2; z[3] = z3; z[4] = z4;
        z[5] = z5; z[6] = z6; z[7] = z7; z[8] = z8; z[9] = z9;
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
//      assert negate >>> 1 == 0;

        int mask = 0 - negate;
        for (int i = 0; i < SIZE; ++i)
        {
            z[i] = (z[i] ^ mask) - mask;
        }
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
        decode128(x, xOff, z, 0);
        decode128(x, xOff + 4, z, 5);
        z[9] &= M24;
    }

    public static void decode(byte[] x, int xOff, int[] z)
    {
        decode128(x, xOff, z, 0);
        decode128(x, xOff + 16, z, 5);
        z[9] &= M24;
    }

    private static void decode128(int[] is, int off, int[] z, int zOff)
    {
        int t0 = is[off + 0], t1 = is[off + 1], t2 = is[off + 2], t3 = is[off + 3];

        z[zOff + 0] = t0 & M26;
        z[zOff + 1] = ((t1 <<  6) | (t0 >>> 26)) & M26;
        z[zOff + 2] = ((t2 << 12) | (t1 >>> 20)) & M25;
        z[zOff + 3] = ((t3 << 19) | (t2 >>> 13)) & M26;
        z[zOff + 4] = t3 >>> 7;
    }

    private static void decode128(byte[] bs, int off, int[] z, int zOff)
    {
        int t0 = decode32(bs, off + 0);
        int t1 = decode32(bs, off + 4);
        int t2 = decode32(bs, off + 8);
        int t3 = decode32(bs, off + 12);

        z[zOff + 0] = t0 & M26;
        z[zOff + 1] = ((t1 <<  6) | (t0 >>> 26)) & M26;
        z[zOff + 2] = ((t2 << 12) | (t1 >>> 20)) & M25;
        z[zOff + 3] = ((t3 << 19) | (t2 >>> 13)) & M26;
        z[zOff + 4] = t3 >>> 7;
    }

    private static int decode32(byte[] bs, int off)
    {
        int n = bs[off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF) << 16;
        n |=  bs[++off]         << 24;
        return n;
    }

    public static void encode(int[] x, int[] z, int zOff)
    {
        encode128(x, 0, z, zOff);
        encode128(x, 5, z, zOff + 4);
    }

    public static void encode(int[] x, byte[] z, int zOff)
    {
        encode128(x, 0, z, zOff);
        encode128(x, 5, z, zOff + 16);
    }

    private static void encode128(int[] x, int xOff, int[] is, int off)
    {
        int x0 = x[xOff + 0], x1 = x[xOff + 1], x2 = x[xOff + 2], x3 = x[xOff + 3], x4 = x[xOff + 4];

        is[off + 0] =  x0         | (x1 << 26);
        is[off + 1] = (x1 >>>  6) | (x2 << 20);
        is[off + 2] = (x2 >>> 12) | (x3 << 13);
        is[off + 3] = (x3 >>> 19) | (x4 <<  7);
    }

    private static void encode128(int[] x, int xOff, byte[] bs, int off)
    {
        int x0 = x[xOff + 0], x1 = x[xOff + 1], x2 = x[xOff + 2], x3 = x[xOff + 3], x4 = x[xOff + 4];

        int t0 =  x0         | (x1 << 26);  encode32(t0, bs, off + 0);
        int t1 = (x1 >>>  6) | (x2 << 20);  encode32(t1, bs, off + 4);
        int t2 = (x2 >>> 12) | (x3 << 13);  encode32(t2, bs, off + 8);
        int t3 = (x3 >>> 19) | (x4 <<  7);  encode32(t3, bs, off + 12);
    }

    private static void encode32(int n, byte[] bs, int off)
    {
        bs[  off] = (byte)(n       );
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    public static void inv(int[] x, int[] z)
    {
//        int[] x2 = create();
//        int[] t = create();
//        powPm5d8(x, x2, t);
//        sqr(t, 3, t);
//        mul(t, x2, z);

        int[] t = create();
        int[] u = new int[8];

        copy(x, 0, t, 0);
        normalize(t);
        encode(t, u, 0);

        Mod.modOddInverse(P32, u, u);

        decode(u, 0, z);
    }

    public static void invVar(int[] x, int[] z)
    {
        int[] t = create();
        int[] u = new int[8];

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
        int x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3], x4 = x[4];
        int x5 = x[5], x6 = x[6], x7 = x[7], x8 = x[8], x9 = x[9];
        long c0, c1, c2, c3;

        c0  = (long)x2 * y; x2 = (int)c0 & M25; c0 >>= 25;
        c1  = (long)x4 * y; x4 = (int)c1 & M25; c1 >>= 25;
        c2  = (long)x7 * y; x7 = (int)c2 & M25; c2 >>= 25;
//        c3  = (long)x9 * y; x9 = (int)c3 & M24; c3 >>= 24;
//        c3 *= 19;
        c3  = (long)x9 * y; x9 = (int)c3 & M25; c3 >>= 25;
        c3 *= 38;

        c3 += (long)x0 * y; z[0] = (int)c3 & M26; c3 >>= 26;
        c1 += (long)x5 * y; z[5] = (int)c1 & M26; c1 >>= 26;

        c3 += (long)x1 * y; z[1] = (int)c3 & M26; c3 >>= 26;
        c0 += (long)x3 * y; z[3] = (int)c0 & M26; c0 >>= 26;
        c1 += (long)x6 * y; z[6] = (int)c1 & M26; c1 >>= 26;
        c2 += (long)x8 * y; z[8] = (int)c2 & M26; c2 >>= 26;

        z[2] = x2 + (int)c3;
        z[4] = x4 + (int)c0;
        z[7] = x7 + (int)c1;
        z[9] = x9 + (int)c2;
    }

    public static void mul(int[] x, int[] y, int[] z)
    {
        int x0 = x[0], y0 = y[0];
        int x1 = x[1], y1 = y[1];
        int x2 = x[2], y2 = y[2];
        int x3 = x[3], y3 = y[3];
        int x4 = x[4], y4 = y[4];

        int u0 = x[5], v0 = y[5];
        int u1 = x[6], v1 = y[6];
        int u2 = x[7], v2 = y[7];
        int u3 = x[8], v3 = y[8];
        int u4 = x[9], v4 = y[9];

        long a0  = (long)x0 * y0;
        long a1  = (long)x0 * y1
                 + (long)x1 * y0;
        long a2  = (long)x0 * y2
                 + (long)x1 * y1
                 + (long)x2 * y0;
        long a3  = (long)x1 * y2
                 + (long)x2 * y1;
        a3     <<= 1;
        a3      += (long)x0 * y3
                 + (long)x3 * y0;
        long a4  = (long)x2 * y2;
        a4     <<= 1;
        a4      += (long)x0 * y4
                 + (long)x1 * y3
                 + (long)x3 * y1
                 + (long)x4 * y0;
        long a5  = (long)x1 * y4
                 + (long)x2 * y3
                 + (long)x3 * y2
                 + (long)x4 * y1;
        a5     <<= 1;
        long a6  = (long)x2 * y4
                 + (long)x4 * y2;
        a6     <<= 1;
        a6      += (long)x3 * y3;
        long a7  = (long)x3 * y4
                 + (long)x4 * y3;
        long a8  = (long)x4 * y4;
        a8     <<= 1;

        long b0  = (long)u0 * v0;
        long b1  = (long)u0 * v1
                 + (long)u1 * v0;
        long b2  = (long)u0 * v2
                 + (long)u1 * v1
                 + (long)u2 * v0;
        long b3  = (long)u1 * v2
                 + (long)u2 * v1;
        b3     <<= 1;
        b3      += (long)u0 * v3
                 + (long)u3 * v0;
        long b4  = (long)u2 * v2;
        b4     <<= 1;
        b4      += (long)u0 * v4
                 + (long)u1 * v3
                 + (long)u3 * v1
                 + (long)u4 * v0;
        long b5  = (long)u1 * v4
                 + (long)u2 * v3
                 + (long)u3 * v2
                 + (long)u4 * v1;
//        b5     <<= 1;
        long b6  = (long)u2 * v4
                 + (long)u4 * v2;
        b6     <<= 1;
        b6      += (long)u3 * v3;
        long b7  = (long)u3 * v4
                 + (long)u4 * v3;
        long b8  = (long)u4 * v4;
//        b8     <<= 1;

        a0 -= b5 * 76;
        a1 -= b6 * 38;
        a2 -= b7 * 38;
        a3 -= b8 * 76;

        a5 -= b0;
        a6 -= b1;
        a7 -= b2;
        a8 -= b3;
//        long a9 = -b4;

        x0 += u0; y0 += v0;
        x1 += u1; y1 += v1;
        x2 += u2; y2 += v2;
        x3 += u3; y3 += v3;
        x4 += u4; y4 += v4;

        long c0  = (long)x0 * y0;
        long c1  = (long)x0 * y1
                 + (long)x1 * y0;
        long c2  = (long)x0 * y2
                 + (long)x1 * y1
                 + (long)x2 * y0;
        long c3  = (long)x1 * y2
                 + (long)x2 * y1;
        c3     <<= 1;
        c3      += (long)x0 * y3
                 + (long)x3 * y0;
        long c4  = (long)x2 * y2;
        c4     <<= 1;
        c4      += (long)x0 * y4
                 + (long)x1 * y3
                 + (long)x3 * y1
                 + (long)x4 * y0;
        long c5  = (long)x1 * y4
                 + (long)x2 * y3
                 + (long)x3 * y2
                 + (long)x4 * y1;
        c5     <<= 1;
        long c6  = (long)x2 * y4
                 + (long)x4 * y2;
        c6     <<= 1;
        c6      += (long)x3 * y3;
        long c7  = (long)x3 * y4
                 + (long)x4 * y3;
        long c8  = (long)x4 * y4;
        c8     <<= 1;

        int z8, z9;
        long t;

        t        = a8 + (c3 - a3);
        z8       = (int)t & M26; t >>= 26;
//        t       += a9 + (c4 - a4);
        t       +=      (c4 - a4) - b4;
//        z9       = (int)t & M24; t >>= 24;
//        t        = a0 + (t + ((c5 - a5) << 1)) * 19;
        z9       = (int)t & M25; t >>= 25;
        t        = a0 + (t + c5 - a5) * 38;
        z[0]     = (int)t & M26; t >>= 26;
        t       += a1 + (c6 - a6) * 38;
        z[1]     = (int)t & M26; t >>= 26;
        t       += a2 + (c7 - a7) * 38;
        z[2]     = (int)t & M25; t >>= 25;
        t       += a3 + (c8 - a8) * 38;
        z[3]     = (int)t & M26; t >>= 26;
//        t       += a4 - a9 * 38;
        t       += a4 + b4 * 38;
        z[4]     = (int)t & M25; t >>= 25;
        t       += a5 + (c0 - a0);
        z[5]     = (int)t & M26; t >>= 26;
        t       += a6 + (c1 - a1);
        z[6]     = (int)t & M26; t >>= 26;
        t       += a7 + (c2 - a2);
        z[7]     = (int)t & M25; t >>= 25;
        t       += z8;
        z[8]     = (int)t & M26; t >>= 26;
        z[9]     = z9 + (int)t;
    }

    public static void negate(int[] x, int[] z)
    {
        for (int i = 0; i < SIZE; ++i)
        {
            z[i] = -x[i];
        }
    }

    public static void normalize(int[] z)
    {
        int x = ((z[9] >>> 23) & 1);
        reduce(z, x);
        reduce(z, -x);
//        assert z[9] >>> 24 == 0;
    }

    public static void one(int[] z)
    {
        z[0] = 1;
        for (int i = 1; i < SIZE; ++i)
        {
            z[i] = 0;
        }
    }

    private static void powPm5d8(int[] x, int[] rx2, int[] rz)
    {
        // z = x^((p-5)/8) = x^FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
        // (250 1s) (1 0s) (1 1s)
        // Addition chain: [1] 2 3 5 10 15 25 50 75 125 [250]

        int[] x2 = rx2;         sqr(x, x2);             mul(x, x2, x2);
        int[] x3 = create();    sqr(x2, x3);            mul(x, x3, x3);
        int[] x5 = x3;          sqr(x3, 2, x5);         mul(x2, x5, x5);
        int[] x10 = create();   sqr(x5, 5, x10);        mul(x5, x10, x10);
        int[] x15 = create();   sqr(x10, 5, x15);       mul(x5, x15, x15);
        int[] x25 = x5;         sqr(x15, 10, x25);      mul(x10, x25, x25);
        int[] x50 = x10;        sqr(x25, 25, x50);      mul(x25, x50, x50);
        int[] x75 = x15;        sqr(x50, 25, x75);      mul(x25, x75, x75);
        int[] x125 = x25;       sqr(x75, 50, x125);     mul(x50, x125, x125);
        int[] x250 = x50;       sqr(x125, 125, x250);   mul(x125, x250, x250);

        int[] t = x125;
        sqr(x250, 2, t);
        mul(t, x, rz);
    }

    private static void reduce(int[] z, int x)
    {
        int t = z[9], z9 = t & M24;
        t = (t >> 24) + x;

        long cc = t * 19;
        cc += z[0]; z[0] = (int)cc & M26; cc >>= 26;
        cc += z[1]; z[1] = (int)cc & M26; cc >>= 26;
        cc += z[2]; z[2] = (int)cc & M25; cc >>= 25;
        cc += z[3]; z[3] = (int)cc & M26; cc >>= 26;
        cc += z[4]; z[4] = (int)cc & M25; cc >>= 25;
        cc += z[5]; z[5] = (int)cc & M26; cc >>= 26;
        cc += z[6]; z[6] = (int)cc & M26; cc >>= 26;
        cc += z[7]; z[7] = (int)cc & M25; cc >>= 25;
        cc += z[8]; z[8] = (int)cc & M26; cc >>= 26;
        z[9] = z9 + (int)cc;
    }

    public static void sqr(int[] x, int[] z)
    {
        int x0 = x[0];
        int x1 = x[1];
        int x2 = x[2];
        int x3 = x[3];
        int x4 = x[4];

        int u0 = x[5];
        int u1 = x[6];
        int u2 = x[7];
        int u3 = x[8];
        int u4 = x[9];

        int x1_2 = x1 * 2;
        int x2_2 = x2 * 2;
        int x3_2 = x3 * 2;
        int x4_2 = x4 * 2;

        long a0  = (long)x0 * x0;
        long a1  = (long)x0 * x1_2;
        long a2  = (long)x0 * x2_2
                 + (long)x1 * x1;
        long a3  = (long)x1_2 * x2_2
                 + (long)x0 * x3_2;
        long a4  = (long)x2 * x2_2
                 + (long)x0 * x4_2
                 + (long)x1 * x3_2;
        long a5  = (long)x1_2 * x4_2
                 + (long)x2_2 * x3_2;
        long a6  = (long)x2_2 * x4_2
                 + (long)x3 * x3;
        long a7  = (long)x3 * x4_2;
        long a8  = (long)x4 * x4_2;

        int u1_2 = u1 * 2;
        int u2_2 = u2 * 2;
        int u3_2 = u3 * 2;
        int u4_2 = u4 * 2;
        
        long b0  = (long)u0 * u0;
        long b1  = (long)u0 * u1_2;
        long b2  = (long)u0 * u2_2
                 + (long)u1 * u1;
        long b3  = (long)u1_2 * u2_2
                 + (long)u0 * u3_2;
        long b4  = (long)u2 * u2_2
                 + (long)u0 * u4_2
                 + (long)u1 * u3_2;
        long b5  = (long)u1_2 * u4_2
                 + (long)u2_2 * u3_2;
        long b6  = (long)u2_2 * u4_2
                 + (long)u3 * u3;
        long b7  = (long)u3 * u4_2;
        long b8  = (long)u4 * u4_2;

        a0 -= b5 * 38;
        a1 -= b6 * 38;
        a2 -= b7 * 38;
        a3 -= b8 * 38;

        a5 -= b0;
        a6 -= b1;
        a7 -= b2;
        a8 -= b3;
//        long a9 = -b4;

        x0 += u0;
        x1 += u1;
        x2 += u2;
        x3 += u3;
        x4 += u4;

        x1_2 = x1 * 2;
        x2_2 = x2 * 2;
        x3_2 = x3 * 2;
        x4_2 = x4 * 2;

        long c0  = (long)x0 * x0;
        long c1  = (long)x0 * x1_2;
        long c2  = (long)x0 * x2_2
                 + (long)x1 * x1;
        long c3  = (long)x1_2 * x2_2
                 + (long)x0 * x3_2;
        long c4  = (long)x2 * x2_2
                 + (long)x0 * x4_2
                 + (long)x1 * x3_2;
        long c5  = (long)x1_2 * x4_2
                 + (long)x2_2 * x3_2;
        long c6  = (long)x2_2 * x4_2
                 + (long)x3 * x3;
        long c7  = (long)x3 * x4_2;
        long c8  = (long)x4 * x4_2;

        int z8, z9;
        long t;

        t        = a8 + (c3 - a3);
        z8       = (int)t & M26; t >>= 26;
//        t       += a9 + (c4 - a4);
        t       +=      (c4 - a4) - b4;
//        z9       = (int)t & M24; t >>= 24;
//        t        = a0 + (t + ((c5 - a5) << 1)) * 19;
        z9       = (int)t & M25; t >>= 25;
        t        = a0 + (t + c5 - a5) * 38;
        z[0]     = (int)t & M26; t >>= 26;
        t       += a1 + (c6 - a6) * 38;
        z[1]     = (int)t & M26; t >>= 26;
        t       += a2 + (c7 - a7) * 38;
        z[2]     = (int)t & M25; t >>= 25;
        t       += a3 + (c8 - a8) * 38;
        z[3]     = (int)t & M26; t >>= 26;
//        t       += a4 - a9 * 38;
        t       += a4 + b4 * 38;
        z[4]     = (int)t & M25; t >>= 25;
        t       += a5 + (c0 - a0);
        z[5]     = (int)t & M26; t >>= 26;
        t       += a6 + (c1 - a1);
        z[6]     = (int)t & M26; t >>= 26;
        t       += a7 + (c2 - a2);
        z[7]     = (int)t & M25; t >>= 25;
        t       += z8;
        z[8]     = (int)t & M26; t >>= 26;
        z[9]     = z9 + (int)t;
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
        int[] uv3 = create();
        int[] uv7 = create();

        mul(u, v, uv3);
        sqr(v, uv7);
        mul(uv3, uv7, uv3);
        sqr(uv7, uv7);
        mul(uv7, uv3, uv7);

        int[] t = create();
        int[] x = create();
        powPm5d8(uv7, t, x);
        mul(x, uv3, x);

        int[] vx2 = create();
        sqr(x, vx2);
        mul(vx2, v, vx2);

        sub(vx2, u, t);
        normalize(t);
        if (isZeroVar(t))
        {
            copy(x, 0, z, 0);
            return true;
        }

        add(vx2, u, t);
        normalize(t);
        if (isZeroVar(t))
        {
            mul(x, ROOT_NEG_ONE, z);
            return true;
        }

        return false;
    }

    public static void sub(int[] x, int[] y, int[] z)
    {
        for (int i = 0; i < SIZE; ++i)
        {
            z[i] = x[i] - y[i];
        }
    }

    public static void subOne(int[] z)
    {
        z[0] -= 1;
    }

    public static void zero(int[] z)
    {
        for (int i = 0; i < SIZE; ++i)
        {
            z[i] = 0;
        }
    }
}
