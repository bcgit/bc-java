package org.bouncycastle.math.ec.rfc7748;

public abstract class X448
{
    private static final int C_A = 156326;
    private static final int C_A24 = (C_A + 2)/4;

    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
    private static final int[] S_x = new int[]{ 0x0FFFFFFE, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF,
        0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFE, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF,
        0x0FFFFFFF };

    // 0xF0FAB725013244423ACF03881AFFEB7BDACDD1031C81B9672954459D84C1F823F1BD65643ACE1B5123AC33FF1C69BAF8ACB1197DC99D2720
    private static final int[] PsubS_x = new int[]{ 0x099d2720, 0x0b1197dc, 0x09baf8ac, 0x033ff1c6, 0x0b5123ac,
        0x0643ace1, 0x03f1bd65, 0x084c1f82, 0x0954459d, 0x081b9672, 0x0dd1031c, 0x0eb7bdac, 0x03881aff, 0x0423acf0,
        0x05013244, 0x0f0fab72 };

    private static int[] precompBase = null;

    private static int decode32(byte[] bs, int off)
    {
        int n = bs[  off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
        for (int i = 0; i < 14; ++i)
        {
            n[i] = decode32(k, kOff + i * 4);
        }

        n[ 0] &= 0xFFFFFFFC;
        n[13] |= 0x80000000;
    }

    private static void pointDouble(int[] x, int[] z)
    {
        int[] A = X448Field.create();
        int[] B = X448Field.create();

//        X448Field.apm(x, z, A, B);
        X448Field.add(x, z, A);
        X448Field.sub(x, z, B);
        X448Field.sqr(A, A);
        X448Field.sqr(B, B);
        X448Field.mul(A, B, x);
        X448Field.sub(A, B, A);
        X448Field.mul(A, C_A24, z);
        X448Field.add(z, B, z);
        X448Field.mul(z, A, z);
    }

    public synchronized static void precompute()
    {
        if (precompBase != null)
        {
            return;
        }

        precompBase = new int[X448Field.SIZE * 446];

        int[] xs = precompBase;
        int[] zs = new int[X448Field.SIZE * 445];

        int[] x = X448Field.create();     x[0] = 5;          
        int[] z = X448Field.create();     z[0] = 1;

        int[] n = X448Field.create();
        int[] d = X448Field.create();

//        X448Field.apm(x, z, n, d);
        X448Field.add(x, z, n);
        X448Field.sub(x, z, d);

        int[] c = X448Field.create();     X448Field.copy(d, 0, c, 0);

        int off = 0;
        for (;;)
        {
            X448Field.copy(n, 0, xs, off);

            if (off == (X448Field.SIZE * 445))
            {
                break;
            }

            pointDouble(x, z);

//            X448Field.apm(x, z, n, d);
            X448Field.add(x, z, n);
            X448Field.sub(x, z, d);
            X448Field.mul(n, c, n);
            X448Field.mul(c, d, c);

            X448Field.copy(d, 0, zs, off);

            off += X448Field.SIZE;
        }

        int[] u = X448Field.create();
        X448Field.inv(c, u);

        for (;;)
        {
            X448Field.copy(xs, off, x, 0);

            X448Field.mul(x, u, x);
//            X448Field.normalize(x);
            X448Field.copy(x, 0, precompBase, off);

            if (off == 0)
            {
                break;
            }

            off -= X448Field.SIZE;
            X448Field.copy(zs, off, z, 0);
            X448Field.mul(u, z, u);
        }
    }

    public static void scalarMult(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        int[] n = new int[14];  decodeScalar(k, kOff, n);

        int[] x1 = X448Field.create();        X448Field.decode(u, uOff, x1);
        int[] x2 = X448Field.create();        X448Field.copy(x1, 0, x2, 0);
        int[] z2 = X448Field.create();        z2[0] = 1;
        int[] x3 = X448Field.create();        x3[0] = 1;
        int[] z3 = X448Field.create();

        int[] t1 = X448Field.create();
        int[] t2 = X448Field.create();

//        assert n[13] >>> 31 == 1;

        int bit = 447, swap = 1;
        do
        {
//            X448Field.apm(x3, z3, t1, x3);
            X448Field.add(x3, z3, t1);
            X448Field.sub(x3, z3, x3);
//            X448Field.apm(x2, z2, z3, x2);
            X448Field.add(x2, z2, z3);
            X448Field.sub(x2, z2, x2);

            X448Field.mul(t1, x2, t1);
            X448Field.mul(x3, z3, x3);
            X448Field.sqr(z3, z3);
            X448Field.sqr(x2, x2);

            X448Field.sub(z3, x2, t2);
            X448Field.mul(t2, C_A24, z2);
            X448Field.add(z2, x2, z2);
            X448Field.mul(z2, t2, z2);
            X448Field.mul(x2, z3, x2);

//            X448Field.apm(t1, x3, x3, z3);
            X448Field.sub(t1, x3, z3);
            X448Field.add(t1, x3, x3);
            X448Field.sqr(x3, x3);
            X448Field.sqr(z3, z3);
            X448Field.mul(z3, x1, z3);

            --bit;

            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;
            swap ^= kt;
            X448Field.cswap(swap, x2, x3);
            X448Field.cswap(swap, z2, z3);
            swap = kt;
        }
        while (bit >= 2);

//        assert swap == 0;

        for (int i = 0; i < 2; ++i)
        {
            pointDouble(x2, z2);
        }

        X448Field.inv(z2, z2);
        X448Field.mul(x2, z2, x2);

        X448Field.normalize(x2);
        X448Field.encode(x2, r, rOff);
    }

    public static void scalarMultBase(byte[] k, int kOff, byte[] r, int rOff)
    {
        precompute();

        int[] n = new int[14];  decodeScalar(k, kOff, n);

        int[] x0 = X448Field.create();
        int[] x1 = X448Field.create();        X448Field.copy(S_x, 0, x1, 0);
        int[] z1 = X448Field.create();        z1[0] = 1;        
        int[] x2 = X448Field.create();        X448Field.copy(PsubS_x, 0, x2, 0);
        int[] z2 = X448Field.create();        z2[0] = 1;

        int[] A = X448Field.create();
        int[] B = z1;
        int[] C = x0;
        int[] D = x1;
        int[] E = B;

//        assert n[13] >>> 31 == 1;

        int off = 0, bit = 2, swap = 1;
        do
        {
            X448Field.copy(precompBase, off, x0, 0);
            off += X448Field.SIZE;

            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;
            swap ^= kt;
            X448Field.cswap(swap, x1, x2);
            X448Field.cswap(swap, z1, z2);
            swap = kt;

//            X448Field.apm(x1, z1, A, B);
            X448Field.add(x1, z1, A);
            X448Field.sub(x1, z1, B);
            X448Field.mul(x0, B, C);
            X448Field.carry(A);
//            X448Field.apm(A, C, D, E);
            X448Field.add(A, C, D);
            X448Field.sub(A, C, E);
            X448Field.sqr(D, D);
            X448Field.sqr(E, E);
            X448Field.mul(z2, D, x1);
            X448Field.mul(x2, E, z1);
        }
        while (++bit < 448);

//        assert swap == 1;

        for (int i = 0; i < 2; ++i)
        {
            pointDouble(x1, z1);
        }

        X448Field.inv(z1, z1);
        X448Field.mul(x1, z1, x1);

        X448Field.normalize(x1);
        X448Field.encode(x1, r, rOff);
    }
}
