package org.bouncycastle.math.ec.rfc8032;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat448;

abstract class Scalar448
{
    static final int SIZE = 14;

    private static final int SCALAR_BYTES = SIZE * 4 + 1;

    private static final long M26L = 0x03FFFFFFL;
    private static final long M28L = 0x0FFFFFFFL;
    private static final long M32L = 0xFFFFFFFFL;

    private static final int TARGET_LENGTH = 447;

    private static final int[] L = new int[]{ 0xAB5844F3, 0x2378C292, 0x8DC58F55, 0x216CC272, 0xAED63690, 0xC44EDB49,
        0x7CCA23E9, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x3FFFFFFF };
    private static final int[] LSq = new int[]{ 0x1BA1FEA9, 0xC1ADFBB8, 0x49E0A8B2, 0xB91BF537, 0xE764D815, 0x4525492B,
        0xA2B8716D, 0x4AE17CF6, 0xBA3C47C4, 0xF1A9CC14, 0x7E4D070A, 0x92052BCB, 0x9F823B72, 0xC3402A93, 0x55AC2279,
        0x91BC6149, 0x46E2C7AA, 0x10B66139, 0xD76B1B48, 0xE2276DA4, 0xBE6511F4, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x0FFFFFFF };

    private static final int L_0 = 0x04A7BB0D;      // L_0:26/24
    private static final int L_1 = 0x0873D6D5;      // L_1:27/23
    private static final int L_2 = 0x0A70AADC;      // L_2:27/26
    private static final int L_3 = 0x03D8D723;      // L_3:26/--
    private static final int L_4 = 0x096FDE93;      // L_4:27/25
    private static final int L_5 = 0x0B65129C;      // L_5:27/26
    private static final int L_6 = 0x063BB124;      // L_6:27/--
    private static final int L_7 = 0x08335DC1;      // L_7:27/22

    private static final int L4_0 = 0x029EEC34;     // L4_0:25/24
    private static final int L4_1 = 0x01CF5B55;     // L4_1:25/--
    private static final int L4_2 = 0x09C2AB72;     // L4_2:27/25
    private static final int L4_3 = 0x0F635C8E;     // L4_3:28/--
    private static final int L4_4 = 0x05BF7A4C;     // L4_4:26/25
    private static final int L4_5 = 0x0D944A72;     // L4_5:28/--
    private static final int L4_6 = 0x08EEC492;     // L4_6:27/24
    private static final int L4_7 = 0x20CD7705;     // L4_7:29/24

    static boolean checkVar(byte[] s, int[] n)
    {
        if (s[SCALAR_BYTES - 1] != 0x00)
        {
            return false;
        }

        decode(s, n);
        return !Nat.gte(SIZE, n, L);
    }

    static void decode(byte[] k, int[] n)
    {
//        assert k[SCALAR_BYTES - 1] == 0x00;

        Codec.decode32(k, 0, n, 0, SIZE);
    }

    static void getOrderWnafVar(int width, byte[] ws)
    {
        Wnaf.getSignedVar(L, width, ws);
    }

    static void multiply225Var(int[] x, int[] y225, int[] z)
    {
//        assert y225[7] >> 31 == y225[7];

        int[] tt = new int[22];
        Nat.mul(y225, 0, 8, x, 0, SIZE, tt, 0);

        if (y225[7] < 0)
        {
            Nat.addTo(SIZE, L, 0, tt, 8);
            Nat.subFrom(SIZE, x, 0, tt, 8);
        }

        byte[] bytes = new byte[88];
        Codec.encode32(tt, 0, 22, bytes, 0);

        byte[] r = reduce704(bytes);
        decode(r, z);
    }

    static byte[] reduce704(byte[] n)
    {
        long x00 =  Codec.decode32(n,   0)       & M32L;    // x00:32/--
        long x01 = (Codec.decode24(n,   4) << 4) & M32L;    // x01:28/--
        long x02 =  Codec.decode32(n,   7)       & M32L;    // x02:32/--
        long x03 = (Codec.decode24(n,  11) << 4) & M32L;    // x03:28/--
        long x04 =  Codec.decode32(n,  14)       & M32L;    // x04:32/--
        long x05 = (Codec.decode24(n,  18) << 4) & M32L;    // x05:28/--
        long x06 =  Codec.decode32(n,  21)       & M32L;    // x06:32/--
        long x07 = (Codec.decode24(n,  25) << 4) & M32L;    // x07:28/--
        long x08 =  Codec.decode32(n,  28)       & M32L;    // x08:32/--
        long x09 = (Codec.decode24(n,  32) << 4) & M32L;    // x09:28/--
        long x10 =  Codec.decode32(n,  35)       & M32L;    // x10:32/--
        long x11 = (Codec.decode24(n,  39) << 4) & M32L;    // x11:28/--
        long x12 =  Codec.decode32(n,  42)       & M32L;    // x12:32/--
        long x13 = (Codec.decode24(n,  46) << 4) & M32L;    // x13:28/--
        long x14 =  Codec.decode32(n,  49)       & M32L;    // x14:32/--
        long x15 = (Codec.decode24(n,  53) << 4) & M32L;    // x15:28/--
        long x16 =  Codec.decode32(n,  56)       & M32L;    // x16:32/--
        long x17 = (Codec.decode24(n,  60) << 4) & M32L;    // x17:28/--
        long x18 =  Codec.decode32(n,  63)       & M32L;    // x18:32/--
        long x19 = (Codec.decode24(n,  67) << 4) & M32L;    // x19:28/--
        long x20 =  Codec.decode32(n,  70)       & M32L;    // x20:32/--
        long x21 = (Codec.decode24(n,  74) << 4) & M32L;    // x21:28/--
        long x22 =  Codec.decode32(n,  77)       & M32L;    // x22:32/--
        long x23 = (Codec.decode24(n,  81) << 4) & M32L;    // x23:28/--
        long x24 =  Codec.decode32(n,  84)       & M32L;    // x24:32/--
        long x25 =  0L                                & M32L;

        x25 += (x24 >>> 28); x24 &= M28L;           // x25:28/--, x24:28/--
        x09 += x25 * L4_0;                          // x09:54/--
        x10 += x25 * L4_1;                          // x10:54/53
        x11 += x25 * L4_2;                          // x11:56/--
        x12 += x25 * L4_3;                          // x12:57/--
        x13 += x25 * L4_4;                          // x13:57/55
        x14 += x25 * L4_5;                          // x14:58/--
        x15 += x25 * L4_6;                          // x15:58/56
        x16 += x25 * L4_7;                          // x16:59/--

        x21 += (x20 >>> 28); x20 &= M28L;           // x21:58/--, x20:28/--
        x22 += (x21 >>> 28); x21 &= M28L;           // x22:57/54, x21:28/--
        x23 += (x22 >>> 28); x22 &= M28L;           // x23:45/42, x22:28/--
        x24 += (x23 >>> 28); x23 &= M28L;           // x24:28/18, x23:28/--

        x08 += x24 * L4_0;                          // x08:54/--
        x09 += x24 * L4_1;                          // x09:55/--
        x10 += x24 * L4_2;                          // x10:56/46
        x11 += x24 * L4_3;                          // x11:57/46
        x12 += x24 * L4_4;                          // x12:57/55
        x13 += x24 * L4_5;                          // x13:58/--
        x14 += x24 * L4_6;                          // x14:58/56
        x15 += x24 * L4_7;                          // x15:59/--

        x07 += x23 * L4_0;                          // x07:54/--
        x08 += x23 * L4_1;                          // x08:54/53
        x09 += x23 * L4_2;                          // x09:56/53
        x10 += x23 * L4_3;                          // x10:57/46
        x11 += x23 * L4_4;                          // x11:57/55
        x12 += x23 * L4_5;                          // x12:58/--
        x13 += x23 * L4_6;                          // x13:58/56
        x14 += x23 * L4_7;                          // x14:59/--

        x06 += x22 * L4_0;                          // x06:54/--
        x07 += x22 * L4_1;                          // x07:54/53
        x08 += x22 * L4_2;                          // x08:56/--
        x09 += x22 * L4_3;                          // x09:57/53
        x10 += x22 * L4_4;                          // x10:57/55
        x11 += x22 * L4_5;                          // x11:58/--
        x12 += x22 * L4_6;                          // x12:58/56
        x13 += x22 * L4_7;                          // x13:59/--

        x18 += (x17 >>> 28); x17 &= M28L;           // x18:59/31, x17:28/--
        x19 += (x18 >>> 28); x18 &= M28L;           // x19:58/54, x18:28/--
        x20 += (x19 >>> 28); x19 &= M28L;           // x20:30/29, x19:28/--
        x21 += (x20 >>> 28); x20 &= M28L;           // x21:28/03, x20:28/--

        x05 += x21 * L4_0;                          // x05:54/--
        x06 += x21 * L4_1;                          // x06:55/--
        x07 += x21 * L4_2;                          // x07:56/31
        x08 += x21 * L4_3;                          // x08:57/31
        x09 += x21 * L4_4;                          // x09:57/56
        x10 += x21 * L4_5;                          // x10:58/--
        x11 += x21 * L4_6;                          // x11:58/56
        x12 += x21 * L4_7;                          // x12:59/--

        x04 += x20 * L4_0;                          // x04:54/--
        x05 += x20 * L4_1;                          // x05:54/53
        x06 += x20 * L4_2;                          // x06:56/53
        x07 += x20 * L4_3;                          // x07:57/31
        x08 += x20 * L4_4;                          // x08:57/55
        x09 += x20 * L4_5;                          // x09:58/--
        x10 += x20 * L4_6;                          // x10:58/56
        x11 += x20 * L4_7;                          // x11:59/--

        x03 += x19 * L4_0;                          // x03:54/--
        x04 += x19 * L4_1;                          // x04:54/53
        x05 += x19 * L4_2;                          // x05:56/--
        x06 += x19 * L4_3;                          // x06:57/53
        x07 += x19 * L4_4;                          // x07:57/55
        x08 += x19 * L4_5;                          // x08:58/--
        x09 += x19 * L4_6;                          // x09:58/56
        x10 += x19 * L4_7;                          // x10:59/--

        x15 += (x14 >>> 28); x14 &= M28L;           // x15:59/31, x14:28/--
        x16 += (x15 >>> 28); x15 &= M28L;           // x16:59/32, x15:28/--
        x17 += (x16 >>> 28); x16 &= M28L;           // x17:31/29, x16:28/--
        x18 += (x17 >>> 28); x17 &= M28L;           // x18:28/04, x17:28/--

        x02 += x18 * L4_0;                          // x02:54/--
        x03 += x18 * L4_1;                          // x03:55/--
        x04 += x18 * L4_2;                          // x04:56/32
        x05 += x18 * L4_3;                          // x05:57/32
        x06 += x18 * L4_4;                          // x06:57/56
        x07 += x18 * L4_5;                          // x07:58/--
        x08 += x18 * L4_6;                          // x08:58/56
        x09 += x18 * L4_7;                          // x09:59/--

        x01 += x17 * L4_0;                          // x01:54/--
        x02 += x17 * L4_1;                          // x02:54/53
        x03 += x17 * L4_2;                          // x03:56/53
        x04 += x17 * L4_3;                          // x04:57/32
        x05 += x17 * L4_4;                          // x05:57/55
        x06 += x17 * L4_5;                          // x06:58/--
        x07 += x17 * L4_6;                          // x07:58/56
        x08 += x17 * L4_7;                          // x08:59/--

        x16 *= 4;
        x16 += (x15 >>> 26); x15 &= M26L;
        x16 += 1;                                   // x16:30/01

        x00 += x16 * L_0;
        x01 += x16 * L_1;
        x02 += x16 * L_2;
        x03 += x16 * L_3;
        x04 += x16 * L_4;
        x05 += x16 * L_5;
        x06 += x16 * L_6;
        x07 += x16 * L_7;

        x01 += (x00 >>> 28); x00 &= M28L;
        x02 += (x01 >>> 28); x01 &= M28L;
        x03 += (x02 >>> 28); x02 &= M28L;
        x04 += (x03 >>> 28); x03 &= M28L;
        x05 += (x04 >>> 28); x04 &= M28L;
        x06 += (x05 >>> 28); x05 &= M28L;
        x07 += (x06 >>> 28); x06 &= M28L;
        x08 += (x07 >>> 28); x07 &= M28L;
        x09 += (x08 >>> 28); x08 &= M28L;
        x10 += (x09 >>> 28); x09 &= M28L;
        x11 += (x10 >>> 28); x10 &= M28L;
        x12 += (x11 >>> 28); x11 &= M28L;
        x13 += (x12 >>> 28); x12 &= M28L;
        x14 += (x13 >>> 28); x13 &= M28L;
        x15 += (x14 >>> 28); x14 &= M28L;
        x16  = (x15 >>> 26); x15 &= M26L;

        x16 -= 1;

//        assert x16 == 0L || x16 == -1L;

        x00 -= x16 & L_0;
        x01 -= x16 & L_1;
        x02 -= x16 & L_2;
        x03 -= x16 & L_3;
        x04 -= x16 & L_4;
        x05 -= x16 & L_5;
        x06 -= x16 & L_6;
        x07 -= x16 & L_7;

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;
        x09 += (x08 >> 28); x08 &= M28L;
        x10 += (x09 >> 28); x09 &= M28L;
        x11 += (x10 >> 28); x10 &= M28L;
        x12 += (x11 >> 28); x11 &= M28L;
        x13 += (x12 >> 28); x12 &= M28L;
        x14 += (x13 >> 28); x13 &= M28L;
        x15 += (x14 >> 28); x14 &= M28L;

//        assert x15 >>> 26 == 0L;

        byte[] r = new byte[SCALAR_BYTES];
        Codec.encode56(x00 | (x01 << 28), r,  0);
        Codec.encode56(x02 | (x03 << 28), r,  7);
        Codec.encode56(x04 | (x05 << 28), r, 14);
        Codec.encode56(x06 | (x07 << 28), r, 21);
        Codec.encode56(x08 | (x09 << 28), r, 28);
        Codec.encode56(x10 | (x11 << 28), r, 35);
        Codec.encode56(x12 | (x13 << 28), r, 42);
        Codec.encode56(x14 | (x15 << 28), r, 49);
//        r[SCALAR_BYTES - 1] = 0;
        return r;
    }

    static byte[] reduce912(byte[] n)
    {
        long x00 =  Codec.decode32(n,   0)       & M32L;    // x00:32/--
        long x01 = (Codec.decode24(n,   4) << 4) & M32L;    // x01:28/--
        long x02 =  Codec.decode32(n,   7)       & M32L;    // x02:32/--
        long x03 = (Codec.decode24(n,  11) << 4) & M32L;    // x03:28/--
        long x04 =  Codec.decode32(n,  14)       & M32L;    // x04:32/--
        long x05 = (Codec.decode24(n,  18) << 4) & M32L;    // x05:28/--
        long x06 =  Codec.decode32(n,  21)       & M32L;    // x06:32/--
        long x07 = (Codec.decode24(n,  25) << 4) & M32L;    // x07:28/--
        long x08 =  Codec.decode32(n,  28)       & M32L;    // x08:32/--
        long x09 = (Codec.decode24(n,  32) << 4) & M32L;    // x09:28/--
        long x10 =  Codec.decode32(n,  35)       & M32L;    // x10:32/--
        long x11 = (Codec.decode24(n,  39) << 4) & M32L;    // x11:28/--
        long x12 =  Codec.decode32(n,  42)       & M32L;    // x12:32/--
        long x13 = (Codec.decode24(n,  46) << 4) & M32L;    // x13:28/--
        long x14 =  Codec.decode32(n,  49)       & M32L;    // x14:32/--
        long x15 = (Codec.decode24(n,  53) << 4) & M32L;    // x15:28/--
        long x16 =  Codec.decode32(n,  56)       & M32L;    // x16:32/--
        long x17 = (Codec.decode24(n,  60) << 4) & M32L;    // x17:28/--
        long x18 =  Codec.decode32(n,  63)       & M32L;    // x18:32/--
        long x19 = (Codec.decode24(n,  67) << 4) & M32L;    // x19:28/--
        long x20 =  Codec.decode32(n,  70)       & M32L;    // x20:32/--
        long x21 = (Codec.decode24(n,  74) << 4) & M32L;    // x21:28/--
        long x22 =  Codec.decode32(n,  77)       & M32L;    // x22:32/--
        long x23 = (Codec.decode24(n,  81) << 4) & M32L;    // x23:28/--
        long x24 =  Codec.decode32(n,  84)       & M32L;    // x24:32/--
        long x25 = (Codec.decode24(n,  88) << 4) & M32L;    // x25:28/--
        long x26 =  Codec.decode32(n,  91)       & M32L;    // x26:32/--
        long x27 = (Codec.decode24(n,  95) << 4) & M32L;    // x27:28/--
        long x28 =  Codec.decode32(n,  98)       & M32L;    // x28:32/--
        long x29 = (Codec.decode24(n, 102) << 4) & M32L;    // x29:28/--
        long x30 =  Codec.decode32(n, 105)       & M32L;    // x30:32/--
        long x31 = (Codec.decode24(n, 109) << 4) & M32L;    // x31:28/--
        long x32 =  Codec.decode16(n, 112)       & M32L;    // x32:16/--

//        x32 += (x31 >>> 28); x31 &= M28L;
        x16 += x32 * L4_0;                          // x16:42/--
        x17 += x32 * L4_1;                          // x17:41/28
        x18 += x32 * L4_2;                          // x18:43/42
        x19 += x32 * L4_3;                          // x19:44/28
        x20 += x32 * L4_4;                          // x20:43/--
        x21 += x32 * L4_5;                          // x21:44/28
        x22 += x32 * L4_6;                          // x22:43/41
        x23 += x32 * L4_7;                          // x23:45/41

        x31 += (x30 >>> 28); x30 &= M28L;           // x31:28/--, x30:28/--
        x15 += x31 * L4_0;                          // x15:54/--
        x16 += x31 * L4_1;                          // x16:53/42
        x17 += x31 * L4_2;                          // x17:55/54
        x18 += x31 * L4_3;                          // x18:56/44
        x19 += x31 * L4_4;                          // x19:55/--
        x20 += x31 * L4_5;                          // x20:56/43
        x21 += x31 * L4_6;                          // x21:55/53
        x22 += x31 * L4_7;                          // x22:57/53

//        x30 += (x29 >>> 28); x29 &= M28L;
        x14 += x30 * L4_0;                          // x14:54/--
        x15 += x30 * L4_1;                          // x15:54/53
        x16 += x30 * L4_2;                          // x16:56/--
        x17 += x30 * L4_3;                          // x17:57/--
        x18 += x30 * L4_4;                          // x18:56/55
        x19 += x30 * L4_5;                          // x19:56/55
        x20 += x30 * L4_6;                          // x20:57/--
        x21 += x30 * L4_7;                          // x21:57/56

        x29 += (x28 >>> 28); x28 &= M28L;           // x29:28/--, x28:28/--
        x13 += x29 * L4_0;                          // x13:54/--
        x14 += x29 * L4_1;                          // x14:54/53
        x15 += x29 * L4_2;                          // x15:56/--
        x16 += x29 * L4_3;                          // x16:57/--
        x17 += x29 * L4_4;                          // x17:57/55
        x18 += x29 * L4_5;                          // x18:57/55
        x19 += x29 * L4_6;                          // x19:57/52
        x20 += x29 * L4_7;                          // x20:58/52

//        x28 += (x27 >>> 28); x27 &= M28L;
        x12 += x28 * L4_0;                          // x12:54/--
        x13 += x28 * L4_1;                          // x13:54/53
        x14 += x28 * L4_2;                          // x14:56/--
        x15 += x28 * L4_3;                          // x15:57/--
        x16 += x28 * L4_4;                          // x16:57/55
        x17 += x28 * L4_5;                          // x17:58/--
        x18 += x28 * L4_6;                          // x18:58/--
        x19 += x28 * L4_7;                          // x19:58/53

        x27 += (x26 >>> 28); x26 &= M28L;           // x27:28/--, x26:28/--
        x11 += x27 * L4_0;                          // x11:54/--
        x12 += x27 * L4_1;                          // x12:54/53
        x13 += x27 * L4_2;                          // x13:56/--
        x14 += x27 * L4_3;                          // x14:57/--
        x15 += x27 * L4_4;                          // x15:57/55
        x16 += x27 * L4_5;                          // x16:58/--
        x17 += x27 * L4_6;                          // x17:58/56
        x18 += x27 * L4_7;                          // x18:59/--

//        x26 += (x25 >>> 28); x25 &= M28L;
        x10 += x26 * L4_0;                          // x10:54/--
        x11 += x26 * L4_1;                          // x11:54/53
        x12 += x26 * L4_2;                          // x12:56/--
        x13 += x26 * L4_3;                          // x13:57/--
        x14 += x26 * L4_4;                          // x14:57/55
        x15 += x26 * L4_5;                          // x15:58/--
        x16 += x26 * L4_6;                          // x16:58/56
        x17 += x26 * L4_7;                          // x17:59/--

        x25 += (x24 >>> 28); x24 &= M28L;           // x25:28/--, x24:28/--
        x09 += x25 * L4_0;                          // x09:54/--
        x10 += x25 * L4_1;                          // x10:54/53
        x11 += x25 * L4_2;                          // x11:56/--
        x12 += x25 * L4_3;                          // x12:57/--
        x13 += x25 * L4_4;                          // x13:57/55
        x14 += x25 * L4_5;                          // x14:58/--
        x15 += x25 * L4_6;                          // x15:58/56
        x16 += x25 * L4_7;                          // x16:59/--

        x21 += (x20 >>> 28); x20 &= M28L;           // x21:58/--, x20:28/--
        x22 += (x21 >>> 28); x21 &= M28L;           // x22:57/54, x21:28/--
        x23 += (x22 >>> 28); x22 &= M28L;           // x23:45/42, x22:28/--
        x24 += (x23 >>> 28); x23 &= M28L;           // x24:28/18, x23:28/--

        x08 += x24 * L4_0;                          // x08:54/--
        x09 += x24 * L4_1;                          // x09:55/--
        x10 += x24 * L4_2;                          // x10:56/46
        x11 += x24 * L4_3;                          // x11:57/46
        x12 += x24 * L4_4;                          // x12:57/55
        x13 += x24 * L4_5;                          // x13:58/--
        x14 += x24 * L4_6;                          // x14:58/56
        x15 += x24 * L4_7;                          // x15:59/--

        x07 += x23 * L4_0;                          // x07:54/--
        x08 += x23 * L4_1;                          // x08:54/53
        x09 += x23 * L4_2;                          // x09:56/53
        x10 += x23 * L4_3;                          // x10:57/46
        x11 += x23 * L4_4;                          // x11:57/55
        x12 += x23 * L4_5;                          // x12:58/--
        x13 += x23 * L4_6;                          // x13:58/56
        x14 += x23 * L4_7;                          // x14:59/--

        x06 += x22 * L4_0;                          // x06:54/--
        x07 += x22 * L4_1;                          // x07:54/53
        x08 += x22 * L4_2;                          // x08:56/--
        x09 += x22 * L4_3;                          // x09:57/53
        x10 += x22 * L4_4;                          // x10:57/55
        x11 += x22 * L4_5;                          // x11:58/--
        x12 += x22 * L4_6;                          // x12:58/56
        x13 += x22 * L4_7;                          // x13:59/--

        x18 += (x17 >>> 28); x17 &= M28L;           // x18:59/31, x17:28/--
        x19 += (x18 >>> 28); x18 &= M28L;           // x19:58/54, x18:28/--
        x20 += (x19 >>> 28); x19 &= M28L;           // x20:30/29, x19:28/--
        x21 += (x20 >>> 28); x20 &= M28L;           // x21:28/03, x20:28/--

        x05 += x21 * L4_0;                          // x05:54/--
        x06 += x21 * L4_1;                          // x06:55/--
        x07 += x21 * L4_2;                          // x07:56/31
        x08 += x21 * L4_3;                          // x08:57/31
        x09 += x21 * L4_4;                          // x09:57/56
        x10 += x21 * L4_5;                          // x10:58/--
        x11 += x21 * L4_6;                          // x11:58/56
        x12 += x21 * L4_7;                          // x12:59/--

        x04 += x20 * L4_0;                          // x04:54/--
        x05 += x20 * L4_1;                          // x05:54/53
        x06 += x20 * L4_2;                          // x06:56/53
        x07 += x20 * L4_3;                          // x07:57/31
        x08 += x20 * L4_4;                          // x08:57/55
        x09 += x20 * L4_5;                          // x09:58/--
        x10 += x20 * L4_6;                          // x10:58/56
        x11 += x20 * L4_7;                          // x11:59/--

        x03 += x19 * L4_0;                          // x03:54/--
        x04 += x19 * L4_1;                          // x04:54/53
        x05 += x19 * L4_2;                          // x05:56/--
        x06 += x19 * L4_3;                          // x06:57/53
        x07 += x19 * L4_4;                          // x07:57/55
        x08 += x19 * L4_5;                          // x08:58/--
        x09 += x19 * L4_6;                          // x09:58/56
        x10 += x19 * L4_7;                          // x10:59/--

        x15 += (x14 >>> 28); x14 &= M28L;           // x15:59/31, x14:28/--
        x16 += (x15 >>> 28); x15 &= M28L;           // x16:59/32, x15:28/--
        x17 += (x16 >>> 28); x16 &= M28L;           // x17:31/29, x16:28/--
        x18 += (x17 >>> 28); x17 &= M28L;           // x18:28/04, x17:28/--

        x02 += x18 * L4_0;                          // x02:54/--
        x03 += x18 * L4_1;                          // x03:55/--
        x04 += x18 * L4_2;                          // x04:56/32
        x05 += x18 * L4_3;                          // x05:57/32
        x06 += x18 * L4_4;                          // x06:57/56
        x07 += x18 * L4_5;                          // x07:58/--
        x08 += x18 * L4_6;                          // x08:58/56
        x09 += x18 * L4_7;                          // x09:59/--

        x01 += x17 * L4_0;                          // x01:54/--
        x02 += x17 * L4_1;                          // x02:54/53
        x03 += x17 * L4_2;                          // x03:56/53
        x04 += x17 * L4_3;                          // x04:57/32
        x05 += x17 * L4_4;                          // x05:57/55
        x06 += x17 * L4_5;                          // x06:58/--
        x07 += x17 * L4_6;                          // x07:58/56
        x08 += x17 * L4_7;                          // x08:59/--

        x16 *= 4;
        x16 += (x15 >>> 26); x15 &= M26L;
        x16 += 1;                                   // x16:30/01

        x00 += x16 * L_0;
        x01 += x16 * L_1;
        x02 += x16 * L_2;
        x03 += x16 * L_3;
        x04 += x16 * L_4;
        x05 += x16 * L_5;
        x06 += x16 * L_6;
        x07 += x16 * L_7;

        x01 += (x00 >>> 28); x00 &= M28L;
        x02 += (x01 >>> 28); x01 &= M28L;
        x03 += (x02 >>> 28); x02 &= M28L;
        x04 += (x03 >>> 28); x03 &= M28L;
        x05 += (x04 >>> 28); x04 &= M28L;
        x06 += (x05 >>> 28); x05 &= M28L;
        x07 += (x06 >>> 28); x06 &= M28L;
        x08 += (x07 >>> 28); x07 &= M28L;
        x09 += (x08 >>> 28); x08 &= M28L;
        x10 += (x09 >>> 28); x09 &= M28L;
        x11 += (x10 >>> 28); x10 &= M28L;
        x12 += (x11 >>> 28); x11 &= M28L;
        x13 += (x12 >>> 28); x12 &= M28L;
        x14 += (x13 >>> 28); x13 &= M28L;
        x15 += (x14 >>> 28); x14 &= M28L;
        x16  = (x15 >>> 26); x15 &= M26L;

        x16 -= 1;

//        assert x16 == 0L || x16 == -1L;

        x00 -= x16 & L_0;
        x01 -= x16 & L_1;
        x02 -= x16 & L_2;
        x03 -= x16 & L_3;
        x04 -= x16 & L_4;
        x05 -= x16 & L_5;
        x06 -= x16 & L_6;
        x07 -= x16 & L_7;

        x01 += (x00 >> 28); x00 &= M28L;
        x02 += (x01 >> 28); x01 &= M28L;
        x03 += (x02 >> 28); x02 &= M28L;
        x04 += (x03 >> 28); x03 &= M28L;
        x05 += (x04 >> 28); x04 &= M28L;
        x06 += (x05 >> 28); x05 &= M28L;
        x07 += (x06 >> 28); x06 &= M28L;
        x08 += (x07 >> 28); x07 &= M28L;
        x09 += (x08 >> 28); x08 &= M28L;
        x10 += (x09 >> 28); x09 &= M28L;
        x11 += (x10 >> 28); x10 &= M28L;
        x12 += (x11 >> 28); x11 &= M28L;
        x13 += (x12 >> 28); x12 &= M28L;
        x14 += (x13 >> 28); x13 &= M28L;
        x15 += (x14 >> 28); x14 &= M28L;

//        assert x15 >>> 26 == 0L;

        byte[] r = new byte[SCALAR_BYTES];
        Codec.encode56(x00 | (x01 << 28), r,  0);
        Codec.encode56(x02 | (x03 << 28), r,  7);
        Codec.encode56(x04 | (x05 << 28), r, 14);
        Codec.encode56(x06 | (x07 << 28), r, 21);
        Codec.encode56(x08 | (x09 << 28), r, 28);
        Codec.encode56(x10 | (x11 << 28), r, 35);
        Codec.encode56(x12 | (x13 << 28), r, 42);
        Codec.encode56(x14 | (x15 << 28), r, 49);
//        r[SCALAR_BYTES - 1] = 0;
        return r;
    }

    static void reduceBasisVar(int[] k, int[] z0, int[] z1)
    {
        /*
         * Split scalar k into two half-size scalars z0 and z1, such that z1 * k == z0 mod L.
         * 
         * See https://ia.cr/2020/454 (Pornin).
         */

        int[] Nu = new int[28];     System.arraycopy(LSq, 0, Nu, 0, 28);
        int[] Nv = new int[28];     Nat448.square(k, Nv); ++Nv[0];
        int[] p  = new int[28];     Nat448.mul(L, k, p);
        int[] u0 = new int[8];      System.arraycopy(L, 0, u0, 0, 8);
        int[] u1 = new int[8];
        int[] v0 = new int[8];      System.arraycopy(k, 0, v0, 0, 8);
        int[] v1 = new int[8];      v1[0] = 1;

        int last = 27;
        int len_Nv = ScalarUtil.getBitLengthPositive(last, Nv);

        while (len_Nv > TARGET_LENGTH)
        {
            int len_p = ScalarUtil.getBitLength(last, p);
            int s = len_p - len_Nv;
            s &= ~(s >> 31);

            if (p[last] < 0)
            {
                ScalarUtil.addShifted_NP(last, s, Nu, Nv, p);
                ScalarUtil.addShifted_UV(7, s, u0, u1, v0, v1);
            }
            else
            {
                ScalarUtil.subShifted_NP(last, s, Nu, Nv, p);
                ScalarUtil.subShifted_UV(7, s, u0, u1, v0, v1);
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

//        assert v0[7] >> 31 == v0[7];
//        assert v1[7] >> 31 == v1[7];

        // v1 * k == v0 mod L
        System.arraycopy(v0, 0, z0, 0, 8);
        System.arraycopy(v1, 0, z1, 0, 8);
    }

    static void toSignedDigits(int bits, int[] x, int[] z)
    {
//        assert 448 < bits && bits < 480;
//        assert z.length > SIZE;

        z[SIZE] = (1 << (bits - 448))
                + Nat.cadd(SIZE, ~x[0] & 1, x, L, z);
//        int c =
        Nat.shiftDownBit(SIZE + 1, z, 0);
//        assert c == (1 << 31);
    }
}
