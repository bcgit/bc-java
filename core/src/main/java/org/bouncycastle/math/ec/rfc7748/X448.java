package org.bouncycastle.math.ec.rfc7748;

import java.security.SecureRandom;

import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;

public abstract class X448
{
    public static class Friend
    {
        private static final Friend INSTANCE = new Friend();
        private Friend() {}
    }

    public static final int POINT_SIZE = 56;
    public static final int SCALAR_SIZE = 56;

    private static class F extends X448Field {};

    private static final int C_A = 156326;
    private static final int C_A24 = (C_A + 2)/4;

//    private static final int[] SQRT_156324 = { 0x0551B193, 0x07A21E17, 0x0E635AD3, 0x00812ABB, 0x025B3F99, 0x01605224,
//        0x0AF8CB32, 0x0D2E7D68, 0x06BA50FD, 0x08E55693, 0x0CB08EB4, 0x02ABEBC1, 0x051BA0BB, 0x02F8812E, 0x0829B611,
//        0x0BA4D3A0 };

    public static boolean calculateAgreement(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        scalarMult(k, kOff, u, uOff, r, rOff);
        return !Arrays.areAllZeroes(r, rOff, POINT_SIZE);
    }

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

    public static void generatePrivateKey(SecureRandom random, byte[] k)
    {
        random.nextBytes(k);

        k[0] &= 0xFC;
        k[SCALAR_SIZE - 1] |= 0x80;
    }

    public static void generatePublicKey(byte[] k, int kOff, byte[] r, int rOff)
    {
        scalarMultBase(k, kOff, r, rOff);
    }

    private static void pointDouble(int[] x, int[] z)
    {
        int[] a = F.create();
        int[] b = F.create();

//        F.apm(x, z, a, b);
        F.add(x, z, a);
        F.sub(x, z, b);
        F.sqr(a, a);
        F.sqr(b, b);
        F.mul(a, b, x);
        F.sub(a, b, a);
        F.mul(a, C_A24, z);
        F.add(z, b, z);
        F.mul(z, a, z);
    }

    public static void precompute()
    {
        Ed448.precompute();
    }

    public static void scalarMult(byte[] k, int kOff, byte[] u, int uOff, byte[] r, int rOff)
    {
        int[] n = new int[14];      decodeScalar(k, kOff, n);

        int[] x1 = F.create();      F.decode(u, uOff, x1);
        int[] x2 = F.create();      F.copy(x1, 0, x2, 0);
        int[] z2 = F.create();      z2[0] = 1;
        int[] x3 = F.create();      x3[0] = 1;
        int[] z3 = F.create();

        int[] t1 = F.create();
        int[] t2 = F.create();

//        assert n[13] >>> 31 == 1;

        int bit = 447, swap = 1;
        do
        {
//            F.apm(x3, z3, t1, x3);
            F.add(x3, z3, t1);
            F.sub(x3, z3, x3);
//            F.apm(x2, z2, z3, x2);
            F.add(x2, z2, z3);
            F.sub(x2, z2, x2);

            F.mul(t1, x2, t1);
            F.mul(x3, z3, x3);
            F.sqr(z3, z3);
            F.sqr(x2, x2);

            F.sub(z3, x2, t2);
            F.mul(t2, C_A24, z2);
            F.add(z2, x2, z2);
            F.mul(z2, t2, z2);
            F.mul(x2, z3, x2);

//            F.apm(t1, x3, x3, z3);
            F.sub(t1, x3, z3);
            F.add(t1, x3, x3);
            F.sqr(x3, x3);
            F.sqr(z3, z3);
            F.mul(z3, x1, z3);

            --bit;

            int word = bit >>> 5, shift = bit & 0x1F;
            int kt = (n[word] >>> shift) & 1;
            swap ^= kt;
            F.cswap(swap, x2, x3);
            F.cswap(swap, z2, z3);
            swap = kt;
        }
        while (bit >= 2);

//        assert swap == 0;

        for (int i = 0; i < 2; ++i)
        {
            pointDouble(x2, z2);
        }

        F.inv(z2, z2);
        F.mul(x2, z2, x2);

        F.normalize(x2);
        F.encode(x2, r, rOff);
    }

    public static void scalarMultBase(byte[] k, int kOff, byte[] r, int rOff)
    {
        int[] x = F.create();
        int[] y = F.create();

        Ed448.scalarMultBaseXY(Friend.INSTANCE, k, kOff, x, y);

        F.inv(x, x);
        F.mul(x, y, x);
        F.sqr(x, x);

        F.normalize(x);
        F.encode(x, r, rOff);
    }
}
