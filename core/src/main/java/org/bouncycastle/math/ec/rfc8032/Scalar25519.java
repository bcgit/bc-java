package org.bouncycastle.math.ec.rfc8032;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;

abstract class Scalar25519
{
    static final int SIZE = 8;

    private static final int SCALAR_BYTES = SIZE * 4;

    private static final long M08L = 0x000000FFL;
    private static final long M28L = 0x0FFFFFFFL;
    private static final long M32L = 0xFFFFFFFFL;

    private static final int TARGET_LENGTH = 254;

    private static final int[] L = new int[]{ 0x5CF5D3ED, 0x5812631A, 0xA2F79CD6, 0x14DEF9DE, 0x00000000, 0x00000000,
        0x00000000, 0x10000000 };
    private static final int[] LSq = new int[]{ 0xAB128969, 0xE2EDF685, 0x2298A31D, 0x68039276, 0xD217F5BE, 0x3DCEEC73,
        0x1B7C309A, 0xA1B39941, 0x4B9EBA7D, 0xCB024C63, 0xD45EF39A, 0x029BDF3B, 0x00000000, 0x00000000, 0x00000000,
        0x01000000 };

    private static final int L0 = -0x030A2C13;      // L0:26/--
    private static final int L1 =  0x012631A6;      // L1:24/22
    private static final int L2 =  0x079CD658;      // L2:27/--
    private static final int L3 = -0x006215D1;      // L3:23/--
    private static final int L4 =  0x000014DF;      // L4:12/11

    static boolean checkVar(byte[] s, int[] n)
    {
        decode(s, n);
        return !Nat256.gte(n, L);
    }

    static void decode(byte[] k, int[] n)
    {
        Codec.decode32(k, 0, n, 0, SIZE);
    }

    static void getOrderWnafVar(int width, byte[] ws)
    {
        Wnaf.getSignedVar(L, width, ws);
    }

    static void multiply128Var(int[] x, int[] y128, int[] z)
    {
        int[] tt = new int[12];
        Nat256.mul128(x, y128, tt);

        if ((int)y128[3] < 0)
        {
            Nat256.addTo(L, 0, tt, 4, 0);
            Nat256.subFrom(x, 0, tt, 4, 0);
        }

        byte[] bytes = new byte[48];
        Codec.encode32(tt, 0, 12, bytes, 0);

        byte[] r = reduce384(bytes);
        decode(r, z);
    }

    static byte[] reduce384(byte[] n)
    {
        long x00 =  Codec.decode32(n,  0)       & M32L;         // x00:32/--
        long x01 = (Codec.decode24(n,  4) << 4) & M32L;         // x01:28/--
        long x02 =  Codec.decode32(n,  7)       & M32L;         // x02:32/--
        long x03 = (Codec.decode24(n, 11) << 4) & M32L;         // x03:28/--
        long x04 =  Codec.decode32(n, 14)       & M32L;         // x04:32/--
        long x05 = (Codec.decode24(n, 18) << 4) & M32L;         // x05:28/--
        long x06 =  Codec.decode32(n, 21)       & M32L;         // x06:32/--
        long x07 = (Codec.decode24(n, 25) << 4) & M32L;         // x07:28/--
        long x08 =  Codec.decode32(n, 28)       & M32L;         // x08:32/--
        long x09 = (Codec.decode24(n, 32) << 4) & M32L;         // x09:28/--
        long x10 =  Codec.decode32(n, 35)       & M32L;         // x10:32/--
        long x11 = (Codec.decode24(n, 39) << 4) & M32L;         // x11:28/--
        long x12 =  Codec.decode32(n, 42)       & M32L;         // x12:32/--
        long x13 = (Codec.decode16(n, 46) << 4) & M32L;         // x13:20/--
        long t;

        // TODO Fix bounds calculations which were copied from Reduce512

        x13 += (x12 >> 28); x12 &= M28L;            // x13:28/22, x12:28/--
        x04 -= x13 * L0;                            // x04:54/49
        x05 -= x13 * L1;                            // x05:54/53
        x06 -= x13 * L2;                            // x06:56/--
        x07 -= x13 * L3;                            // x07:56/52
        x08 -= x13 * L4;                            // x08:56/52

        x12 += (x11 >> 28); x11 &= M28L;            // x12:28/24, x11:28/--
        x03 -= x12 * L0;                            // x03:54/49
        x04 -= x12 * L1;                            // x04:54/51
        x05 -= x12 * L2;                            // x05:56/--
        x06 -= x12 * L3;                            // x06:56/52
        x07 -= x12 * L4;                            // x07:56/53

        x11 += (x10 >> 28); x10 &= M28L;            // x11:29/--, x10:28/--
        x02 -= x11 * L0;                            // x02:55/32
        x03 -= x11 * L1;                            // x03:55/--
        x04 -= x11 * L2;                            // x04:56/55
        x05 -= x11 * L3;                            // x05:56/52
        x06 -= x11 * L4;                            // x06:56/53

        x10 += (x09 >> 28); x09 &= M28L;            // x10:29/--, x09:28/--
        x01 -= x10 * L0;                            // x01:55/28
        x02 -= x10 * L1;                            // x02:55/54
        x03 -= x10 * L2;                            // x03:56/55
        x04 -= x10 * L3;                            // x04:57/--
        x05 -= x10 * L4;                            // x05:56/53

        x08 += (x07 >> 28); x07 &= M28L;            // x08:56/53, x07:28/--
        x09 += (x08 >> 28); x08 &= M28L;            // x09:29/25, x08:28/--

        t    = x08 >>> 27;
        x09 += t;                                   // x09:29/26

        x00 -= x09 * L0;                            // x00:55/53
        x01 -= x09 * L1;                            // x01:55/54
        x02 -= x09 * L2;                            // x02:57/--
        x03 -= x09 * L3;                            // x03:57/--
        x04 -= x09 * L4;                            // x04:57/42

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;
        x09  = (x08 >> 28); x08 &= M28L;

        x09 -= t;

//        assert x09 == 0L || x09 == -1L;

        x00 += x09 & L0;
        x01 += x09 & L1;
        x02 += x09 & L2;
        x03 += x09 & L3;
        x04 += x09 & L4;

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;

        byte[] r = new byte[64];
        Codec.encode56(x00 | (x01 << 28), r,  0);
        Codec.encode56(x02 | (x03 << 28), r,  7);
        Codec.encode56(x04 | (x05 << 28), r, 14);
        Codec.encode56(x06 | (x07 << 28), r, 21);
        Codec.encode32((int)x08,          r, 28);
        return r;
    }

    static byte[] reduce512(byte[] n)
    {
        long x00 =  Codec.decode32(n,  0)       & M32L;         // x00:32/--
        long x01 = (Codec.decode24(n,  4) << 4) & M32L;         // x01:28/--
        long x02 =  Codec.decode32(n,  7)       & M32L;         // x02:32/--
        long x03 = (Codec.decode24(n, 11) << 4) & M32L;         // x03:28/--
        long x04 =  Codec.decode32(n, 14)       & M32L;         // x04:32/--
        long x05 = (Codec.decode24(n, 18) << 4) & M32L;         // x05:28/--
        long x06 =  Codec.decode32(n, 21)       & M32L;         // x06:32/--
        long x07 = (Codec.decode24(n, 25) << 4) & M32L;         // x07:28/--
        long x08 =  Codec.decode32(n, 28)       & M32L;         // x08:32/--
        long x09 = (Codec.decode24(n, 32) << 4) & M32L;         // x09:28/--
        long x10 =  Codec.decode32(n, 35)       & M32L;         // x10:32/--
        long x11 = (Codec.decode24(n, 39) << 4) & M32L;         // x11:28/--
        long x12 =  Codec.decode32(n, 42)       & M32L;         // x12:32/--
        long x13 = (Codec.decode24(n, 46) << 4) & M32L;         // x13:28/--
        long x14 =  Codec.decode32(n, 49)       & M32L;         // x14:32/--
        long x15 = (Codec.decode24(n, 53) << 4) & M32L;         // x15:28/--
        long x16 =  Codec.decode32(n, 56)       & M32L;         // x16:32/--
        long x17 = (Codec.decode24(n, 60) << 4) & M32L;         // x17:28/--
        long x18 =                 n[63]        & M08L;         // x18:08/--
        long t;

//        x18 += (x17 >> 28); x17 &= M28L;
        x09 -= x18 * L0;                            // x09:34/28
        x10 -= x18 * L1;                            // x10:33/30
        x11 -= x18 * L2;                            // x11:35/28
        x12 -= x18 * L3;                            // x12:32/31
        x13 -= x18 * L4;                            // x13:28/21

        x17 += (x16 >> 28); x16 &= M28L;            // x17:28/--, x16:28/--
        x08 -= x17 * L0;                            // x08:54/32
        x09 -= x17 * L1;                            // x09:52/51
        x10 -= x17 * L2;                            // x10:55/34
        x11 -= x17 * L3;                            // x11:51/36
        x12 -= x17 * L4;                            // x12:41/--

//        x16 += (x15 >> 28); x15 &= M28L;
        x07 -= x16 * L0;                            // x07:54/28
        x08 -= x16 * L1;                            // x08:54/53
        x09 -= x16 * L2;                            // x09:55/53
        x10 -= x16 * L3;                            // x10:55/52
        x11 -= x16 * L4;                            // x11:51/41

        x15 += (x14 >> 28); x14 &= M28L;            // x15:28/--, x14:28/--
        x06 -= x15 * L0;                            // x06:54/32
        x07 -= x15 * L1;                            // x07:54/53
        x08 -= x15 * L2;                            // x08:56/--
        x09 -= x15 * L3;                            // x09:55/54
        x10 -= x15 * L4;                            // x10:55/53

//        x14 += (x13 >> 28); x13 &= M28L;
        x05 -= x14 * L0;                            // x05:54/28
        x06 -= x14 * L1;                            // x06:54/53
        x07 -= x14 * L2;                            // x07:56/--
        x08 -= x14 * L3;                            // x08:56/51
        x09 -= x14 * L4;                            // x09:56/--

        x13 += (x12 >> 28); x12 &= M28L;            // x13:28/22, x12:28/--
        x04 -= x13 * L0;                            // x04:54/49
        x05 -= x13 * L1;                            // x05:54/53
        x06 -= x13 * L2;                            // x06:56/--
        x07 -= x13 * L3;                            // x07:56/52
        x08 -= x13 * L4;                            // x08:56/52

        x12 += (x11 >> 28); x11 &= M28L;            // x12:28/24, x11:28/--
        x03 -= x12 * L0;                            // x03:54/49
        x04 -= x12 * L1;                            // x04:54/51
        x05 -= x12 * L2;                            // x05:56/--
        x06 -= x12 * L3;                            // x06:56/52
        x07 -= x12 * L4;                            // x07:56/53

        x11 += (x10 >> 28); x10 &= M28L;            // x11:29/--, x10:28/--
        x02 -= x11 * L0;                            // x02:55/32
        x03 -= x11 * L1;                            // x03:55/--
        x04 -= x11 * L2;                            // x04:56/55
        x05 -= x11 * L3;                            // x05:56/52
        x06 -= x11 * L4;                            // x06:56/53

        x10 += (x09 >> 28); x09 &= M28L;            // x10:29/--, x09:28/--
        x01 -= x10 * L0;                            // x01:55/28
        x02 -= x10 * L1;                            // x02:55/54
        x03 -= x10 * L2;                            // x03:56/55
        x04 -= x10 * L3;                            // x04:57/--
        x05 -= x10 * L4;                            // x05:56/53

        x08 += (x07 >> 28); x07 &= M28L;            // x08:56/53, x07:28/--
        x09 += (x08 >> 28); x08 &= M28L;            // x09:29/25, x08:28/--

        t    = x08 >>> 27;
        x09 += t;                                   // x09:29/26

        x00 -= x09 * L0;                            // x00:55/53
        x01 -= x09 * L1;                            // x01:55/54
        x02 -= x09 * L2;                            // x02:57/--
        x03 -= x09 * L3;                            // x03:57/--
        x04 -= x09 * L4;                            // x04:57/42

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;
        x09  = (x08 >> 28); x08 &= M28L;

        x09 -= t;

//        assert x09 == 0L || x09 == -1L;

        x00 += x09 & L0;
        x01 += x09 & L1;
        x02 += x09 & L2;
        x03 += x09 & L3;
        x04 += x09 & L4;

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;

        byte[] r = new byte[SCALAR_BYTES];
        Codec.encode56(x00 | (x01 << 28), r,  0);
        Codec.encode56(x02 | (x03 << 28), r,  7);
        Codec.encode56(x04 | (x05 << 28), r, 14);
        Codec.encode56(x06 | (x07 << 28), r, 21);
        Codec.encode32((int)x08,          r, 28);
        return r;
    }

    static void reduceBasisVar(int[] k, int[] z0, int[] z1)
    {
        /*
         * Split scalar k into two half-size scalars z0 and z1, such that z1 * k == z0 mod L.
         * 
         * See https://ia.cr/2020/454 (Pornin).
         */

        int[] Nu = new int[16];     System.arraycopy(LSq, 0, Nu, 0, 16);
        int[] Nv = new int[16];     Nat256.square(k, Nv); ++Nv[0];
        int[] p  = new int[16];     Nat256.mul(L, k, p);
        int[] u0 = new int[4];      System.arraycopy(L, 0, u0, 0, 4);
        int[] u1 = new int[4];
        int[] v0 = new int[4];      System.arraycopy(k, 0, v0, 0, 4);
        int[] v1 = new int[4];      v1[0] = 1;

        int last = 15;
        int len_Nv = ScalarUtil.getBitLengthPositive(last, Nv);

        while (len_Nv > TARGET_LENGTH)
        {
            int len_p = ScalarUtil.getBitLength(last, p);
            int s = len_p - len_Nv;
            s &= ~(s >> 31);

            if (p[last] < 0)
            {
                ScalarUtil.addShifted_NP(last, s, Nu, Nv, p);
                ScalarUtil.addShifted_UV(3, s, u0, u1, v0, v1);
            }
            else
            {
                ScalarUtil.subShifted_NP(last, s, Nu, Nv, p);
                ScalarUtil.subShifted_UV(3, s, u0, u1, v0, v1);
            }

            if (ScalarUtil.lessThan(last, Nu, Nv))
            {
                int[] t0 = u0; u0 = v0; v0 = t0;
                int[] t1 = u1; u1 = v1; v1 = t1;
                int[] tN = Nu; Nu = Nv; Nv = tN;

                last = len_Nv >>> 5;
                len_Nv = ScalarUtil.getBitLengthPositive(last, Nv);
            }
        }

        // v1 * k == v0 mod L
        System.arraycopy(v0, 0, z0, 0, 4);
        System.arraycopy(v1, 0, z1, 0, 4);
    }

    static void toSignedDigits(int bits, int[] z)
    {
//        assert bits == 256;
//        assert z.length >= SIZE;

//        int c1 =
        Nat.caddTo(SIZE, ~z[0] & 1, L, z);     //assert c1 == 0;
//        int c2 =
        Nat.shiftDownBit(SIZE, z, 1);           //assert c2 == (1 << 31);
    }
}
