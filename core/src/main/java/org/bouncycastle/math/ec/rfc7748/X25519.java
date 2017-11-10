package org.bouncycastle.math.ec.rfc7748;

public abstract class X25519
{
    private static final int C_A = 486662;
    private static final int C_A24 = (C_A + 2)/4;

    // 0x1
//    private static final int[] S_x = new int[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    // 0x215132111D8354CB52385F46DCA2B71D440F6A51EB4D1207816B1E0137D48290
    private static final int[] PsubS_x = new int[]{ 0x03D48290, 0x02C7804D, 0x01207816, 0x028F5A68, 0x00881ED4, 0x00A2B71D,
        0x0217D1B7, 0x014CB523, 0x0088EC1A, 0x0042A264 };

    private static int[] precompBase = null;

    private static int decode32(byte[] bs, int off)
    {
        int n = bs[off] & 0xFF;
        n |= (bs[++off] & 0xFF) << 8;
        n |= (bs[++off] & 0xFF) << 16;
        n |=  bs[++off]         << 24;
        return n;
    }

    private static void decodeScalar(byte[] k, int kOff, int[] n)
    {
        for (int i = 0; i < 8; ++i)
        {
            n[i] = decode32(k, kOff + i * 4);
        }

        n[0] &= 0xFFFFFFF8;
        n[7] &= 0x7FFFFFFF;
        n[7] |= 0x40000000;
    }

    private static void pointDouble(int[] x, int[] z)
    {
        int[] A = X25519Field.create();
        int[] B = X25519Field.create();

        X25519Field.apm(x, z, A, B);
        X25519Field.sqr(A, A);
        X25519Field.sqr(B, B);
        X25519Field.mul(A, B, x);
        X25519Field.sub(A, B, A);
        X25519Field.mul(A, C_A24, z);
        X25519Field.add(z, B, z);
        X25519Field.mul(z, A, z);
    }

    public synchronized static void precompute()
    {
        if (precompBase != null)
        {
            return;
        }

        precompBase = new int[X25519Field.SIZE * 252];

        int[] xs = precompBase;
        int[] zs = new int[X25519Field.SIZE * 251];

        int[] x = X25519Field.create();     x[0] = 9;          
        int[] z = X25519Field.create();     z[0] = 1;

        int[] n = X25519Field.create();
        int[] d = X25519Field.create();

        X25519Field.apm(x, z, n, d);

        int[] c = X25519Field.create();     X25519Field.copy(d, 0, c, 0);

        int off = 0;
        for (;;)
        {
            X25519Field.copy(n, 0, xs, off);

            if (off == (X25519Field.SIZE * 251))
            {
                break;
            }

            pointDouble(x, z);

            X25519Field.apm(x, z, n, d);
            X25519Field.mul(n, c, n);
            X25519Field.mul(c, d, c);

            X25519Field.copy(d, 0, zs, off);

            off += X25519Field.SIZE;
        }

        int[] u = X25519Field.create();
        X25519Field.inv(c, u);

        for (;;)
        {
            X25519Field.copy(xs, off, x, 0);

            X25519Field.mul(x, u, x);
//            X25519Field.normalize(x);
            X25519Field.copy(x, 0, precompBase, off);

            if (off == 0)
            {
                break;
            }

            off -= X25519Field.SIZE;
            X25519Field.copy(zs, off, z, 0);
            X25519Field.mul(u, z, u);
        }
    }

    public static void scalarMult(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        int[] n = new int[8];   decodeScalar(k, kOff, n);

        int[] x1 = X25519Field.create();        X25519Field.decode(u, uOff, x1);
        int[] x2 = X25519Field.create();        X25519Field.copy(x1, 0, x2, 0);
        int[] z2 = X25519Field.create();        z2[0] = 1;
        int[] x3 = X25519Field.create();        x3[0] = 1;
        int[] z3 = X25519Field.create();

        int[] t1 = X25519Field.create();
        int[] t2 = X25519Field.create();

//        assert n[7] >>> 30 == 1;

        int bit = 254, swap = 1;
        do
        {
            X25519Field.apm(x3, z3, t1, x3);
            X25519Field.apm(x2, z2, z3, x2);
            X25519Field.mul(t1, x2, t1);
            X25519Field.mul(x3, z3, x3);
            X25519Field.sqr(z3, z3);
            X25519Field.sqr(x2, x2);

            X25519Field.sub(z3, x2, t2);
            X25519Field.mul(t2, C_A24, z2);
            X25519Field.add(z2, x2, z2);
            X25519Field.mul(z2, t2, z2);
            X25519Field.mul(x2, z3, x2);

            X25519Field.apm(t1, x3, x3, z3);
            X25519Field.sqr(x3, x3);
            X25519Field.sqr(z3, z3);
            X25519Field.mul(z3, x1, z3);

            --bit;

            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;
            swap ^= kt;
            X25519Field.cswap(swap, x2, x3);
            X25519Field.cswap(swap, z2, z3);
            swap = kt;
        }
        while (bit >= 3);

//        assert swap == 0;

        for (int i = 0; i < 3; ++i)
        {
            pointDouble(x2, z2);
        }

        X25519Field.inv(z2, z2);
        X25519Field.mul(x2, z2, x2);

        X25519Field.normalize(x2);
        X25519Field.encode(x2, r, rOff);
    }

    public static void scalarMultBase(byte[] k, int kOff, byte[] r, int rOff)
    {
        precompute();

        int[] n = new int[8];   decodeScalar(k, kOff, n);

        int[] x0 = X25519Field.create();
//        int[] x1 = X25519Field.create();        X25519Field.copy(S_x, 0, x1, 0);
        int[] x1 = X25519Field.create();        x1[0] = 1;
        int[] z1 = X25519Field.create();        z1[0] = 1;        
        int[] x2 = X25519Field.create();        X25519Field.copy(PsubS_x, 0, x2, 0);
        int[] z2 = X25519Field.create();        z2[0] = 1;        

        int[] A = x1;
        int[] B = z1;
        int[] C = x0;
        int[] D = A;
        int[] E = B;

//      assert n[7] >>> 30 == 1;

        int off = 0, bit = 3, swap = 1;
        do
        {
            X25519Field.copy(precompBase, off, x0, 0);
            off += X25519Field.SIZE;

            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;
            swap ^= kt;
            X25519Field.cswap(swap, x1, x2);
            X25519Field.cswap(swap, z1, z2);
            swap = kt;

            X25519Field.apm(x1, z1, A, B);
            X25519Field.mul(x0, B, C);
            X25519Field.carry(A);
            X25519Field.apm(A, C, D, E);
            X25519Field.sqr(D, D);
            X25519Field.sqr(E, E);
            X25519Field.mul(z2, D, x1);
            X25519Field.mul(x2, E, z1);
        }
        while (++bit < 255);

//        assert swap == 1;

        for (int i = 0; i < 3; ++i)
        {
            pointDouble(x1, z1);
        }

        X25519Field.inv(z1, z1);
        X25519Field.mul(x1, z1, x1);

        X25519Field.normalize(x1);
        X25519Field.encode(x1, r, rOff);
    }
}
