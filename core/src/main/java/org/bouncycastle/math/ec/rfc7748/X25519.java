package org.bouncycastle.math.ec.rfc7748;

import java.security.SecureRandom;

import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;

public abstract class X25519
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();
        private Friend() {}
    }

    public static final int POINT_SIZE = 32;
    public static final int SCALAR_SIZE = 32;

    private static final int C_A = 486662;
    private static final int C_A24 = (C_A + 2)/4;

//    private static final int[] SQRT_NEG_486664 = { 0x03457E06, 0x03812ABF, 0x01A82CC6, 0x028A5BE8, 0x018B43A7,
//        0x03FC4F7E, 0x02C23700, 0x006BBD27, 0x03A30500, 0x001E4DDB };

    public static boolean calculateAgreement(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        scalarMult(k, kOff, u, uOff, r, rOff);
        return !Arrays.areAllZeroes(r, rOff, POINT_SIZE);
    }

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

    public static void generatePrivateKey(SecureRandom random, byte[] k)
    {
        random.nextBytes(k);

        k[0] &= 0xF8;
        k[SCALAR_SIZE - 1] &= 0x7F;
        k[SCALAR_SIZE - 1] |= 0x40;
    }

    public static void generatePublicKey(byte[] k, int kOff, byte[] r, int rOff)
    {
        scalarMultBase(k, kOff, r, rOff);
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

    public static void precompute()
    {
        Ed25519.precompute();
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
        int[] y = X25519Field.create();
        int[] z = X25519Field.create();

        Ed25519.scalarMultBaseYZ(Friend.INSTANCE, k, kOff, y, z);

        X25519Field.apm(z, y, y, z);

        X25519Field.inv(z, z);
        X25519Field.mul(y, z, y);

        X25519Field.normalize(y);
        X25519Field.encode(y, r, rOff);
    }
}
