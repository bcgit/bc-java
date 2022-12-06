package org.bouncycastle.pqc.crypto.gemss;

abstract class Mul_GF2x
{
    public abstract void mul_gf2x(Pointer C, Pointer A, Pointer B);

    public abstract void sqr_gf2x(long[] res, long[] A, int a_cp);

    public abstract void mul_gf2x_xor(Pointer res, Pointer A, Pointer B);

    public static class Mul6
        extends Mul_GF2x
    {
        private long[] Buffer;

        public Mul6()
        {
            Buffer = new long[6];
        }

        public void mul_gf2x(Pointer C, Pointer A, Pointer B)
        {
            mul192_no_simd_gf2x(C.array, 0, A.array, A.cp, B.array, B.cp);
        }

        public void sqr_gf2x(long[] res, long[] A, int a_cp)
        {
            SQR64_NO_SIMD_GF2X(res, 4, A[a_cp + 2]);
            SQR128_NO_SIMD_GF2X(res, 0, A, a_cp);
        }

        public void mul_gf2x_xor(Pointer res, Pointer A, Pointer B)
        {
            mul192_no_simd_gf2x_xor(res.array, res.cp, A.array, A.cp, B.array, B.cp, Buffer);
        }

    }

    public static class Mul9
        extends Mul_GF2x
    {
        private long[] Buffer;

        public Mul9()
        {
            Buffer = new long[9];
        }

        public void mul_gf2x(Pointer C, Pointer A, Pointer B)
        {
            mul288_no_simd_gf2x(C.array, 0, A.array, A.cp, B.array, B.cp, Buffer);
        }

        public void sqr_gf2x(long[] res, long[] A, int a_cp)
        {
            res[8] = SQR32_NO_SIMD_GF2X(A[a_cp + 4]);
            SQR256_NO_SIMD_GF2X(res, 0, A, a_cp);
        }

        public void mul_gf2x_xor(Pointer res, Pointer A, Pointer B)
        {
            mul288_no_simd_gf2x_xor(res.array, res.cp, A.array, A.cp, B.array, B.cp, Buffer);
        }
    }

    public static class Mul12
        extends Mul_GF2x
    {
        private long[] Buffer;

        public Mul12()
        {
            Buffer = new long[12];
        }

        public void mul_gf2x(Pointer C, Pointer A, Pointer B)
        {
            mul384_no_simd_gf2x(C.array, A.array, A.cp, B.array, B.cp, Buffer);
        }

        public void sqr_gf2x(long[] res, long[] A, int a_cp)
        {
            SQR128_NO_SIMD_GF2X(res, 8, A, a_cp + 4);
            SQR256_NO_SIMD_GF2X(res, 0, A, a_cp);
        }

        public void mul_gf2x_xor(Pointer res, Pointer A, Pointer B)
        {
            mul384_no_simd_gf2x_xor(res.array, A.array, A.cp, B.array, B.cp, Buffer);
        }
    }

    public static class Mul13
        extends Mul_GF2x
    {
        private long[] Buffer;
        private long[] Buffer2;

        public Mul13()
        {
            Buffer = new long[13];
            Buffer2 = new long[4];
        }

        public void mul_gf2x(Pointer C, Pointer A, Pointer B)
        {
            mul416_no_simd_gf2x(C.array, A.array, A.cp, B.array, B.cp, Buffer);
        }

        public void sqr_gf2x(long[] res, long[] A, int a_cp)
        {
            res[12] = SQR32_NO_SIMD_GF2X(A[a_cp + 6]);
            SQR128_NO_SIMD_GF2X(res, 8, A, a_cp + 4);
            SQR256_NO_SIMD_GF2X(res, 0, A, a_cp);
        }

        public void mul_gf2x_xor(Pointer res, Pointer A, Pointer B)
        {
            mul416_no_simd_gf2x_xor(res.array, A.array, A.cp, B.array, B.cp, Buffer, Buffer2);
        }
    }

    public static class Mul17
        extends Mul_GF2x
    {
        private long[] AA, BB, Buffer1, Buffer2;

        public Mul17()
        {
            AA = new long[5];
            BB = new long[5];
            Buffer1 = new long[17];
            Buffer2 = new long[4];
        }

        public void mul_gf2x(Pointer C, Pointer A, Pointer B)
        {
            mul544_no_simd_gf2x(C.array, A.array, A.cp, B.array, B.cp, AA, BB, Buffer1);
        }

        public void sqr_gf2x(long[] res, long[] A, int a_cp)
        {
            res[16] = SQR32_NO_SIMD_GF2X(A[a_cp + 8]);
            SQR256_NO_SIMD_GF2X(res, 8, A, a_cp + 4);
            SQR256_NO_SIMD_GF2X(res, 0, A, a_cp);
        }

        public void mul_gf2x_xor(Pointer res, Pointer A, Pointer B)
        {
            mul544_no_simd_gf2x_xor(res.array, A.array, A.cp, B.array, B.cp, AA, BB, Buffer1, Buffer2);
        }
    }

    private static long SQR32_NO_SIMD_GF2X(long A)
    {
        A = (A ^ (A << 16)) & (0x0000FFFF0000FFFFL);
        A = (A ^ (A << 8)) & (0x00FF00FF00FF00FFL);
        A = (A ^ (A << 4)) & (0x0F0F0F0F0F0F0F0FL);
        A = (A ^ (A << 2)) & (0x3333333333333333L);
        return (A ^ (A << 1)) & 0x5555555555555555L;
    }

    /* 1+log_2(32)*3 = 1+5*3 = 16 instructions */
    private static long SQR64LOW_NO_SIMD_GF2X(long A)
    {
        A = ((A & 0xFFFFFFFFL) ^ (A << 16)) & (0x0000FFFF0000FFFFL);
        A = (A ^ (A << 8)) & (0x00FF00FF00FF00FFL);
        A = (A ^ (A << 4)) & (0x0F0F0F0F0F0F0F0FL);
        A = (A ^ (A << 2)) & (0x3333333333333333L);
        return (A ^ (A << 1)) & (0x5555555555555555L);
    }

    private static void SQR64_NO_SIMD_GF2X(long[] C, int c_cp, long A)
    {
        C[c_cp + 1] = SQR32_NO_SIMD_GF2X(A >>> 32);
        C[c_cp] = SQR64LOW_NO_SIMD_GF2X(A);
    }

    private static void SQR128_NO_SIMD_GF2X(long[] C, int c_cp, long[] A, int a_cp)
    {
        SQR64_NO_SIMD_GF2X(C, c_cp + 2, A[a_cp + 1]);
        SQR64_NO_SIMD_GF2X(C, c_cp, A[a_cp]);
    }

    private static void SQR256_NO_SIMD_GF2X(long[] C, int c_cp, long[] A, int a_cp)
    {
        SQR128_NO_SIMD_GF2X(C, c_cp + 4, A, a_cp + 2);
        SQR128_NO_SIMD_GF2X(C, c_cp, A, a_cp);
    }

    private static long MUL32_NO_SIMD_GF2X(long a, long b)
    {
        long tmp = (-(b & 1L)) & a;
        tmp ^= ((-((b >>> 1) & 1L)) & a) << 1;
        tmp ^= ((-((b >>> 2) & 1L)) & a) << 2;
        tmp ^= ((-((b >>> 3) & 1L)) & a) << 3;
        tmp ^= ((-((b >>> 4) & 1L)) & a) << 4;
        tmp ^= ((-((b >>> 5) & 1L)) & a) << 5;
        tmp ^= ((-((b >>> 6) & 1L)) & a) << 6;
        tmp ^= ((-((b >>> 7) & 1L)) & a) << 7;
        tmp ^= ((-((b >>> 8) & 1L)) & a) << 8;
        tmp ^= ((-((b >>> 9) & 1L)) & a) << 9;
        tmp ^= ((-((b >>> 10) & 1L)) & a) << 10;
        tmp ^= ((-((b >>> 11) & 1L)) & a) << 11;
        tmp ^= ((-((b >>> 12) & 1L)) & a) << 12;
        tmp ^= ((-((b >>> 13) & 1L)) & a) << 13;
        tmp ^= ((-((b >>> 14) & 1L)) & a) << 14;
        tmp ^= ((-((b >>> 15) & 1L)) & a) << 15;
        tmp ^= ((-((b >>> 16) & 1L)) & a) << 16;
        tmp ^= ((-((b >>> 17) & 1L)) & a) << 17;
        tmp ^= ((-((b >>> 18) & 1L)) & a) << 18;
        tmp ^= ((-((b >>> 19) & 1L)) & a) << 19;
        tmp ^= ((-((b >>> 20) & 1L)) & a) << 20;
        tmp ^= ((-((b >>> 21) & 1L)) & a) << 21;
        tmp ^= ((-((b >>> 22) & 1L)) & a) << 22;
        tmp ^= ((-((b >>> 23) & 1L)) & a) << 23;
        tmp ^= ((-((b >>> 24) & 1L)) & a) << 24;
        tmp ^= ((-((b >>> 25) & 1L)) & a) << 25;
        tmp ^= ((-((b >>> 26) & 1L)) & a) << 26;
        tmp ^= ((-((b >>> 27) & 1L)) & a) << 27;
        tmp ^= ((-((b >>> 28) & 1L)) & a) << 28;
        tmp ^= ((-((b >>> 29) & 1L)) & a) << 29;
        tmp ^= ((-((b >>> 30) & 1L)) & a) << 30;
        tmp ^= ((-((b >>> 31) & 1L)) & a) << 31;
        return tmp;
    }

    private static void MUL64_NO_SIMD_GF2X(long[] C, int c_cp, long A, long B)
    {
        long c0, c1, tmp;
        c0 = (-(B & 1L)) & A;
        /* Optimization: the '&1' is removed */
        tmp = ((-(B >>> 63)) & A);
        c0 ^= tmp << 63;
        c1 = tmp >>> 1;
        tmp = ((-((B >>> 1) & 1L)) & A);
        c0 ^= tmp << 1;
        c1 ^= tmp >>> 63;
        tmp = ((-((B >>> 2) & 1L)) & A);
        c0 ^= tmp << 2;
        c1 ^= tmp >>> 62;
        tmp = ((-((B >>> 3) & 1L)) & A);
        c0 ^= tmp << 3;
        c1 ^= tmp >>> 61;
        tmp = ((-((B >>> 4) & 1L)) & A);
        c0 ^= tmp << 4;
        c1 ^= tmp >>> 60;
        tmp = ((-((B >>> 5) & 1L)) & A);
        c0 ^= tmp << 5;
        c1 ^= tmp >>> 59;
        tmp = ((-((B >>> 6) & 1L)) & A);
        c0 ^= tmp << 6;
        c1 ^= tmp >>> 58;
        tmp = ((-((B >>> 7) & 1L)) & A);
        c0 ^= tmp << 7;
        c1 ^= tmp >>> 57;
        tmp = ((-((B >>> 8) & 1L)) & A);
        c0 ^= tmp << 8;
        c1 ^= tmp >>> 56;
        tmp = ((-((B >>> 9) & 1L)) & A);
        c0 ^= tmp << 9;
        c1 ^= tmp >>> 55;
        tmp = ((-((B >>> 10) & 1L)) & A);
        c0 ^= tmp << 10;
        c1 ^= tmp >>> 54;
        tmp = ((-((B >>> 11) & 1L)) & A);
        c0 ^= tmp << 11;
        c1 ^= tmp >>> 53;
        tmp = ((-((B >>> 12) & 1L)) & A);
        c0 ^= tmp << 12;
        c1 ^= tmp >>> 52;
        tmp = ((-((B >>> 13) & 1L)) & A);
        c0 ^= tmp << 13;
        c1 ^= tmp >>> 51;
        tmp = ((-((B >>> 14) & 1L)) & A);
        c0 ^= tmp << 14;
        c1 ^= tmp >>> 50;
        tmp = ((-((B >>> 15) & 1L)) & A);
        c0 ^= tmp << 15;
        c1 ^= tmp >>> 49;
        tmp = ((-((B >>> 16) & 1L)) & A);
        c0 ^= tmp << 16;
        c1 ^= tmp >>> 48;
        tmp = ((-((B >>> 17) & 1L)) & A);
        c0 ^= tmp << 17;
        c1 ^= tmp >>> 47;
        tmp = ((-((B >>> 18) & 1L)) & A);
        c0 ^= tmp << 18;
        c1 ^= tmp >>> 46;
        tmp = ((-((B >>> 19) & 1L)) & A);
        c0 ^= tmp << 19;
        c1 ^= tmp >>> 45;
        tmp = ((-((B >>> 20) & 1L)) & A);
        c0 ^= tmp << 20;
        c1 ^= tmp >>> 44;
        tmp = ((-((B >>> 21) & 1L)) & A);
        c0 ^= tmp << 21;
        c1 ^= tmp >>> 43;
        tmp = ((-((B >>> 22) & 1L)) & A);
        c0 ^= tmp << 22;
        c1 ^= tmp >>> 42;
        tmp = ((-((B >>> 23) & 1L)) & A);
        c0 ^= tmp << 23;
        c1 ^= tmp >>> 41;
        tmp = ((-((B >>> 24) & 1L)) & A);
        c0 ^= tmp << 24;
        c1 ^= tmp >>> 40;
        tmp = ((-((B >>> 25) & 1L)) & A);
        c0 ^= tmp << 25;
        c1 ^= tmp >>> 39;
        tmp = ((-((B >>> 26) & 1L)) & A);
        c0 ^= tmp << 26;
        c1 ^= tmp >>> 38;
        tmp = ((-((B >>> 27) & 1L)) & A);
        c0 ^= tmp << 27;
        c1 ^= tmp >>> 37;
        tmp = ((-((B >>> 28) & 1L)) & A);
        c0 ^= tmp << 28;
        c1 ^= tmp >>> 36;
        tmp = ((-((B >>> 29) & 1L)) & A);
        c0 ^= tmp << 29;
        c1 ^= tmp >>> 35;
        tmp = ((-((B >>> 30) & 1L)) & A);
        c0 ^= tmp << 30;
        c1 ^= tmp >>> 34;
        tmp = ((-((B >>> 31) & 1L)) & A);
        c0 ^= tmp << 31;
        c1 ^= tmp >>> 33;
        tmp = ((-((B >>> 32) & 1L)) & A);
        c0 ^= tmp << 32;
        c1 ^= tmp >>> 32;
        tmp = ((-((B >>> 33) & 1L)) & A);
        c0 ^= tmp << 33;
        c1 ^= tmp >>> 31;
        tmp = ((-((B >>> 34) & 1L)) & A);
        c0 ^= tmp << 34;
        c1 ^= tmp >>> 30;
        tmp = ((-((B >>> 35) & 1L)) & A);
        c0 ^= tmp << 35;
        c1 ^= tmp >>> 29;
        tmp = ((-((B >>> 36) & 1L)) & A);
        c0 ^= tmp << 36;
        c1 ^= tmp >>> 28;
        tmp = ((-((B >>> 37) & 1L)) & A);
        c0 ^= tmp << 37;
        c1 ^= tmp >>> 27;
        tmp = ((-((B >>> 38) & 1L)) & A);
        c0 ^= tmp << 38;
        c1 ^= tmp >>> 26;
        tmp = ((-((B >>> 39) & 1L)) & A);
        c0 ^= tmp << 39;
        c1 ^= tmp >>> 25;
        tmp = ((-((B >>> 40) & 1L)) & A);
        c0 ^= tmp << 40;
        c1 ^= tmp >>> 24;
        tmp = ((-((B >>> 41) & 1L)) & A);
        c0 ^= tmp << 41;
        c1 ^= tmp >>> 23;
        tmp = ((-((B >>> 42) & 1L)) & A);
        c0 ^= tmp << 42;
        c1 ^= tmp >>> 22;
        tmp = ((-((B >>> 43) & 1L)) & A);
        c0 ^= tmp << 43;
        c1 ^= tmp >>> 21;
        tmp = ((-((B >>> 44) & 1L)) & A);
        c0 ^= tmp << 44;
        c1 ^= tmp >>> 20;
        tmp = ((-((B >>> 45) & 1L)) & A);
        c0 ^= tmp << 45;
        c1 ^= tmp >>> 19;
        tmp = ((-((B >>> 46) & 1L)) & A);
        c0 ^= tmp << 46;
        c1 ^= tmp >>> 18;
        tmp = ((-((B >>> 47) & 1L)) & A);
        c0 ^= tmp << 47;
        c1 ^= tmp >>> 17;
        tmp = ((-((B >>> 48) & 1L)) & A);
        c0 ^= tmp << 48;
        c1 ^= tmp >>> 16;
        tmp = ((-((B >>> 49) & 1L)) & A);
        c0 ^= tmp << 49;
        c1 ^= tmp >>> 15;
        tmp = ((-((B >>> 50) & 1L)) & A);
        c0 ^= tmp << 50;
        c1 ^= tmp >>> 14;
        tmp = ((-((B >>> 51) & 1L)) & A);
        c0 ^= tmp << 51;
        c1 ^= tmp >>> 13;
        tmp = ((-((B >>> 52) & 1L)) & A);
        c0 ^= tmp << 52;
        c1 ^= tmp >>> 12;
        tmp = ((-((B >>> 53) & 1L)) & A);
        c0 ^= tmp << 53;
        c1 ^= tmp >>> 11;
        tmp = ((-((B >>> 54) & 1L)) & A);
        c0 ^= tmp << 54;
        c1 ^= tmp >>> 10;
        tmp = ((-((B >>> 55) & 1L)) & A);
        c0 ^= tmp << 55;
        c1 ^= tmp >>> 9;
        tmp = ((-((B >>> 56) & 1L)) & A);
        c0 ^= tmp << 56;
        c1 ^= tmp >>> 8;
        tmp = ((-((B >>> 57) & 1L)) & A);
        c0 ^= tmp << 57;
        c1 ^= tmp >>> 7;
        tmp = ((-((B >>> 58) & 1L)) & A);
        c0 ^= tmp << 58;
        c1 ^= tmp >>> 6;
        tmp = ((-((B >>> 59) & 1L)) & A);
        c0 ^= tmp << 59;
        c1 ^= tmp >>> 5;
        tmp = ((-((B >>> 60) & 1L)) & A);
        c0 ^= tmp << 60;
        c1 ^= tmp >>> 4;
        tmp = ((-((B >>> 61) & 1L)) & A);
        c0 ^= tmp << 61;
        c1 ^= tmp >>> 3;
        tmp = ((-((B >>> 62) & 1L)) & A);
        C[c_cp] = c0 ^ (tmp << 62);
        C[c_cp + 1] = c1 ^ (tmp >>> 2);
    }

    private static void MUL64_NO_SIMD_GF2X_XOR(long[] C, int c_cp, long A, long B)
    {
        long c0, c1, tmp;
        c0 = (-(B & 1L)) & A;
        /* Optimization: the '&1' is removed */
        tmp = ((-(B >>> 63)) & A);
        c0 ^= tmp << 63;
        c1 = tmp >>> 1;
        tmp = ((-((B >>> 1) & 1L)) & A);
        c0 ^= tmp << 1;
        c1 ^= tmp >>> 63;
        tmp = ((-((B >>> 2) & 1L)) & A);
        c0 ^= tmp << 2;
        c1 ^= tmp >>> 62;
        tmp = ((-((B >>> 3) & 1L)) & A);
        c0 ^= tmp << 3;
        c1 ^= tmp >>> 61;
        tmp = ((-((B >>> 4) & 1L)) & A);
        c0 ^= tmp << 4;
        c1 ^= tmp >>> 60;
        tmp = ((-((B >>> 5) & 1L)) & A);
        c0 ^= tmp << 5;
        c1 ^= tmp >>> 59;
        tmp = ((-((B >>> 6) & 1L)) & A);
        c0 ^= tmp << 6;
        c1 ^= tmp >>> 58;
        tmp = ((-((B >>> 7) & 1L)) & A);
        c0 ^= tmp << 7;
        c1 ^= tmp >>> 57;
        tmp = ((-((B >>> 8) & 1L)) & A);
        c0 ^= tmp << 8;
        c1 ^= tmp >>> 56;
        tmp = ((-((B >>> 9) & 1L)) & A);
        c0 ^= tmp << 9;
        c1 ^= tmp >>> 55;
        tmp = ((-((B >>> 10) & 1L)) & A);
        c0 ^= tmp << 10;
        c1 ^= tmp >>> 54;
        tmp = ((-((B >>> 11) & 1L)) & A);
        c0 ^= tmp << 11;
        c1 ^= tmp >>> 53;
        tmp = ((-((B >>> 12) & 1L)) & A);
        c0 ^= tmp << 12;
        c1 ^= tmp >>> 52;
        tmp = ((-((B >>> 13) & 1L)) & A);
        c0 ^= tmp << 13;
        c1 ^= tmp >>> 51;
        tmp = ((-((B >>> 14) & 1L)) & A);
        c0 ^= tmp << 14;
        c1 ^= tmp >>> 50;
        tmp = ((-((B >>> 15) & 1L)) & A);
        c0 ^= tmp << 15;
        c1 ^= tmp >>> 49;
        tmp = ((-((B >>> 16) & 1L)) & A);
        c0 ^= tmp << 16;
        c1 ^= tmp >>> 48;
        tmp = ((-((B >>> 17) & 1L)) & A);
        c0 ^= tmp << 17;
        c1 ^= tmp >>> 47;
        tmp = ((-((B >>> 18) & 1L)) & A);
        c0 ^= tmp << 18;
        c1 ^= tmp >>> 46;
        tmp = ((-((B >>> 19) & 1L)) & A);
        c0 ^= tmp << 19;
        c1 ^= tmp >>> 45;
        tmp = ((-((B >>> 20) & 1L)) & A);
        c0 ^= tmp << 20;
        c1 ^= tmp >>> 44;
        tmp = ((-((B >>> 21) & 1L)) & A);
        c0 ^= tmp << 21;
        c1 ^= tmp >>> 43;
        tmp = ((-((B >>> 22) & 1L)) & A);
        c0 ^= tmp << 22;
        c1 ^= tmp >>> 42;
        tmp = ((-((B >>> 23) & 1L)) & A);
        c0 ^= tmp << 23;
        c1 ^= tmp >>> 41;
        tmp = ((-((B >>> 24) & 1L)) & A);
        c0 ^= tmp << 24;
        c1 ^= tmp >>> 40;
        tmp = ((-((B >>> 25) & 1L)) & A);
        c0 ^= tmp << 25;
        c1 ^= tmp >>> 39;
        tmp = ((-((B >>> 26) & 1L)) & A);
        c0 ^= tmp << 26;
        c1 ^= tmp >>> 38;
        tmp = ((-((B >>> 27) & 1L)) & A);
        c0 ^= tmp << 27;
        c1 ^= tmp >>> 37;
        tmp = ((-((B >>> 28) & 1L)) & A);
        c0 ^= tmp << 28;
        c1 ^= tmp >>> 36;
        tmp = ((-((B >>> 29) & 1L)) & A);
        c0 ^= tmp << 29;
        c1 ^= tmp >>> 35;
        tmp = ((-((B >>> 30) & 1L)) & A);
        c0 ^= tmp << 30;
        c1 ^= tmp >>> 34;
        tmp = ((-((B >>> 31) & 1L)) & A);
        c0 ^= tmp << 31;
        c1 ^= tmp >>> 33;
        tmp = ((-((B >>> 32) & 1L)) & A);
        c0 ^= tmp << 32;
        c1 ^= tmp >>> 32;
        tmp = ((-((B >>> 33) & 1L)) & A);
        c0 ^= tmp << 33;
        c1 ^= tmp >>> 31;
        tmp = ((-((B >>> 34) & 1L)) & A);
        c0 ^= tmp << 34;
        c1 ^= tmp >>> 30;
        tmp = ((-((B >>> 35) & 1L)) & A);
        c0 ^= tmp << 35;
        c1 ^= tmp >>> 29;
        tmp = ((-((B >>> 36) & 1L)) & A);
        c0 ^= tmp << 36;
        c1 ^= tmp >>> 28;
        tmp = ((-((B >>> 37) & 1L)) & A);
        c0 ^= tmp << 37;
        c1 ^= tmp >>> 27;
        tmp = ((-((B >>> 38) & 1L)) & A);
        c0 ^= tmp << 38;
        c1 ^= tmp >>> 26;
        tmp = ((-((B >>> 39) & 1L)) & A);
        c0 ^= tmp << 39;
        c1 ^= tmp >>> 25;
        tmp = ((-((B >>> 40) & 1L)) & A);
        c0 ^= tmp << 40;
        c1 ^= tmp >>> 24;
        tmp = ((-((B >>> 41) & 1L)) & A);
        c0 ^= tmp << 41;
        c1 ^= tmp >>> 23;
        tmp = ((-((B >>> 42) & 1L)) & A);
        c0 ^= tmp << 42;
        c1 ^= tmp >>> 22;
        tmp = ((-((B >>> 43) & 1L)) & A);
        c0 ^= tmp << 43;
        c1 ^= tmp >>> 21;
        tmp = ((-((B >>> 44) & 1L)) & A);
        c0 ^= tmp << 44;
        c1 ^= tmp >>> 20;
        tmp = ((-((B >>> 45) & 1L)) & A);
        c0 ^= tmp << 45;
        c1 ^= tmp >>> 19;
        tmp = ((-((B >>> 46) & 1L)) & A);
        c0 ^= tmp << 46;
        c1 ^= tmp >>> 18;
        tmp = ((-((B >>> 47) & 1L)) & A);
        c0 ^= tmp << 47;
        c1 ^= tmp >>> 17;
        tmp = ((-((B >>> 48) & 1L)) & A);
        c0 ^= tmp << 48;
        c1 ^= tmp >>> 16;
        tmp = ((-((B >>> 49) & 1L)) & A);
        c0 ^= tmp << 49;
        c1 ^= tmp >>> 15;
        tmp = ((-((B >>> 50) & 1L)) & A);
        c0 ^= tmp << 50;
        c1 ^= tmp >>> 14;
        tmp = ((-((B >>> 51) & 1L)) & A);
        c0 ^= tmp << 51;
        c1 ^= tmp >>> 13;
        tmp = ((-((B >>> 52) & 1L)) & A);
        c0 ^= tmp << 52;
        c1 ^= tmp >>> 12;
        tmp = ((-((B >>> 53) & 1L)) & A);
        c0 ^= tmp << 53;
        c1 ^= tmp >>> 11;
        tmp = ((-((B >>> 54) & 1L)) & A);
        c0 ^= tmp << 54;
        c1 ^= tmp >>> 10;
        tmp = ((-((B >>> 55) & 1L)) & A);
        c0 ^= tmp << 55;
        c1 ^= tmp >>> 9;
        tmp = ((-((B >>> 56) & 1L)) & A);
        c0 ^= tmp << 56;
        c1 ^= tmp >>> 8;
        tmp = ((-((B >>> 57) & 1L)) & A);
        c0 ^= tmp << 57;
        c1 ^= tmp >>> 7;
        tmp = ((-((B >>> 58) & 1L)) & A);
        c0 ^= tmp << 58;
        c1 ^= tmp >>> 6;
        tmp = ((-((B >>> 59) & 1L)) & A);
        c0 ^= tmp << 59;
        c1 ^= tmp >>> 5;
        tmp = ((-((B >>> 60) & 1L)) & A);
        c0 ^= tmp << 60;
        c1 ^= tmp >>> 4;
        tmp = ((-((B >>> 61) & 1L)) & A);
        c0 ^= tmp << 61;
        c1 ^= tmp >>> 3;
        tmp = ((-((B >>> 62) & 1L)) & A);
        C[c_cp] ^= c0 ^ (tmp << 62);
        C[c_cp + 1] ^= c1 ^ (tmp >>> 2);
    }

    private static void mul128_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp)
    {
        MUL64_NO_SIMD_GF2X(C, c_cp, A[a_cp], B[b_cp]);//x0, x1
        MUL64_NO_SIMD_GF2X(C, c_cp + 2, A[a_cp + 1], B[b_cp + 1]);//x2, x3
        C[c_cp + 2] ^= C[c_cp + 1];//c2=x1+x2
        C[c_cp + 1] = C[c_cp] ^ C[c_cp + 2];//c1=x0+x1+x2
        C[c_cp + 2] ^= C[c_cp + 3];//c2=x1+x2+x3
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, A[a_cp] ^ A[a_cp + 1], B[b_cp] ^ B[b_cp + 1]);//x4, x5
    }

    private static void mul128_no_simd_gf2x(long[] C, int c_cp, long a0, long a1, long b0, long b1)
    {
        MUL64_NO_SIMD_GF2X(C, c_cp, a0, b0);//x0, x1
        MUL64_NO_SIMD_GF2X(C, c_cp + 2, a1, b1);//x2, x3
        C[c_cp + 2] ^= C[c_cp + 1];//c2=x1+x2
        C[c_cp + 1] = C[c_cp] ^ C[c_cp + 2];//c1=x0+x1+x2
        C[c_cp + 2] ^= C[c_cp + 3];//c2=x1+x2+x3
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, a0 ^ a1, b0 ^ b1);//x4, x5
    }

    private static void mul128_no_simd_gf2x_xor(long[] C, int c_cp, long a0, long a1, long b0, long b1, long[] RESERVED_BUF)
    {
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, 0, a0, b0);//x0, x1
        //c0=x0, c1=x1
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, 2, a1, b1);//x2, x3
        //c2=x2, c3=x3
        C[c_cp] ^= RESERVED_BUF[0]; //x0
        RESERVED_BUF[2] ^= RESERVED_BUF[1];//x1+x2
        C[c_cp + 1] ^= RESERVED_BUF[0] ^ RESERVED_BUF[2];//x0+x1+x2
        C[c_cp + 2] ^= RESERVED_BUF[2] ^ RESERVED_BUF[3];//x1+x2+x3
        C[c_cp + 3] ^= RESERVED_BUF[3];//x3
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, a0 ^ a1, b0 ^ b1);//x4, x5
    }

    public static void mul192_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp)
    {
        /* A0*B0 */
        MUL64_NO_SIMD_GF2X(C, c_cp, A[a_cp], B[b_cp]);//x0, x1
        /* A2*B2 */
        MUL64_NO_SIMD_GF2X(C, c_cp + 4, A[a_cp + 2], B[b_cp + 2]);//x4,x5
        /* A1*B1 */
        MUL64_NO_SIMD_GF2X(C, c_cp + 2, A[a_cp + 1], B[b_cp + 1]);//x2, x3
        C[c_cp + 1] ^= C[c_cp + 2];//C1=x1^x2
        C[c_cp + 3] ^= C[c_cp + 4];//c3=x3^x4
        C[c_cp + 4] = C[c_cp + 3] ^ C[c_cp + 5];//c4=x3+x4+x5
        C[c_cp + 2] = C[c_cp + 3] ^ C[c_cp + 1] ^ C[c_cp];//c2=x1+x2+x3+x4
        C[c_cp + 3] = C[c_cp + 1] ^ C[c_cp + 4];//c3=x1+x2+x4+x5
        C[c_cp + 1] ^= C[c_cp];
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, A[a_cp] ^ A[a_cp + 1], B[b_cp] ^ B[b_cp + 1]);//x6, x7
        /* (A1+A2)*(B1+B2)  */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 3, A[a_cp + 1] ^ A[a_cp + 2], B[b_cp + 1] ^ B[b_cp + 2]);//x10, x11
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 2, A[a_cp] ^ A[a_cp + 2], B[b_cp] ^ B[b_cp + 2]);//x8, x9
    }

    public static void mul192_no_simd_gf2x_xor(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp, long[] Buffer)
    {
        /* A0*B0 */
        MUL64_NO_SIMD_GF2X(Buffer, 0, A[a_cp], B[b_cp]);//x0, x1
        /* A2*B2 */
        MUL64_NO_SIMD_GF2X(Buffer, 4, A[a_cp + 2], B[b_cp + 2]);//x4,x5
        /* A1*B1 */
        MUL64_NO_SIMD_GF2X(Buffer, 2, A[a_cp + 1], B[b_cp + 1]);//x2, x3
        C[c_cp] ^= Buffer[0];
        Buffer[1] ^= Buffer[2];//C1=x1^x2
        Buffer[3] ^= Buffer[4];//c3=x3^x4
        Buffer[4] = Buffer[3] ^ Buffer[5];//c4=x3+x4+x5
        Buffer[0] ^= Buffer[1];
        C[c_cp + 1] ^= Buffer[0];
        C[c_cp + 2] ^= Buffer[3] ^ Buffer[0];//c2=x1+x2+x3+x4
        C[c_cp + 3] ^= Buffer[1] ^ Buffer[4];//c3=x1+x2+x4+x5
        C[c_cp + 4] ^= Buffer[4];
        C[c_cp + 5] ^= Buffer[5];
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 1, A[a_cp] ^ A[a_cp + 1], B[b_cp] ^ B[b_cp + 1]);//x6, x7
        /* (A1+A2)*(B1+B2)  */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 3, A[a_cp + 1] ^ A[a_cp + 2], B[b_cp + 1] ^ B[b_cp + 2]);//x10, x11
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 2, A[a_cp] ^ A[a_cp + 2], B[b_cp] ^ B[b_cp + 2]);//x8, x9
    }

    private static void mul288_no_simd_gf2x(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp, long[] RESERVED_BUF)
    {
        mul128_no_simd_gf2x(C, c_cp, A[a_cp], A[a_cp + 1], B[b_cp], B[b_cp + 1]);
        MUL64_NO_SIMD_GF2X(C, c_cp + 4, A[a_cp + 2], B[b_cp + 2]); //x0,x1
        MUL64_NO_SIMD_GF2X(C, c_cp + 7, A[a_cp + 3], B[b_cp + 3]);//x2,x3
        C[c_cp + 7] ^= C[c_cp + 5];//x1+x2
        C[c_cp + 8] ^= MUL32_NO_SIMD_GF2X(A[a_cp + 4], B[b_cp + 4]);//x3+x4
        C[c_cp + 5] = C[c_cp + 7] ^ C[c_cp + 4];//x0+x1+x2
        C[c_cp + 7] ^= C[c_cp + 8];//x1+x2+x3+x4
        C[c_cp + 6] = C[c_cp + 7] ^ C[c_cp + 4];//x0+x1+x2+x3+x4
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 5, A[a_cp + 2] ^ A[a_cp + 3], B[b_cp + 2] ^ B[b_cp + 3]);//x4, x5
        /* (A1+A2)*(B1+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 7, A[a_cp + 3] ^ A[a_cp + 4], B[b_cp + 3] ^ B[b_cp + 4]);//x6, x7
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 6, A[a_cp + 2] ^ A[a_cp + 4], B[b_cp + 2] ^ B[b_cp + 4]);//x2,x3
        C[c_cp + 4] ^= C[c_cp + 2];
        C[c_cp + 5] ^= C[c_cp + 3];
        long AA0 = A[a_cp] ^ A[a_cp + 2];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 3];
        long BB0 = B[b_cp] ^ B[b_cp + 2];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 3];
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, 0, AA0, BB0); //x0,x1
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, 2, AA1, BB1);//x2,x3
        RESERVED_BUF[2] ^= RESERVED_BUF[1];//x1+x2
        RESERVED_BUF[3] ^= MUL32_NO_SIMD_GF2X(A[a_cp + 4], B[b_cp + 4]);//x3+x4
        C[c_cp + 2] = C[c_cp + 4] ^ C[c_cp] ^ RESERVED_BUF[0];
        C[c_cp + 3] = C[c_cp + 5] ^ C[c_cp + 1] ^ RESERVED_BUF[2] ^ RESERVED_BUF[0];//x0+x1+x2
        RESERVED_BUF[2] ^= RESERVED_BUF[3];//x1+x2+x3+x4
        C[c_cp + 4] ^= C[c_cp + 6] ^ RESERVED_BUF[2] ^ RESERVED_BUF[0];//x0+x1+x2+x3+x4
        C[c_cp + 5] ^= C[c_cp + 7] ^ RESERVED_BUF[2];
        C[c_cp + 6] ^= C[c_cp + 8] ^ RESERVED_BUF[3];
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 3, AA0 ^ AA1, BB0 ^ BB1);//x4, x5
        /* (A1+A2)*(B1+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 5, AA1 ^ A[a_cp + 4], BB1 ^ B[b_cp + 4]);//x6, x7
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 4, AA0 ^ A[a_cp + 4], BB0 ^ B[b_cp + 4]);//x2,x3
    }

    private static void mul288_no_simd_gf2x_xor(long[] C, int c_cp, long[] A, int a_cp, long[] B, int b_cp, long[] Buffer)
    {
        mul128_no_simd_gf2x(Buffer, 0, A[a_cp], A[a_cp + 1], B[b_cp], B[b_cp + 1]);
        MUL64_NO_SIMD_GF2X(Buffer, 4, A[a_cp + 2], B[b_cp + 2]); //x0,x1
        MUL64_NO_SIMD_GF2X(Buffer, 7, A[a_cp + 3], B[b_cp + 3]);//x2,x3
        Buffer[7] ^= Buffer[5];//x1+x2
        Buffer[8] ^= MUL32_NO_SIMD_GF2X(A[a_cp + 4], B[b_cp + 4]);//x3+x4
        Buffer[5] = Buffer[7] ^ Buffer[4];//x0+x1+x2
        Buffer[7] ^= Buffer[8];//x1+x2+x3+x4
        Buffer[6] = Buffer[7] ^ Buffer[4];//x0+x1+x2+x3+x4
        Buffer[4] ^= Buffer[2];
        Buffer[5] ^= Buffer[3];
        C[c_cp] ^= Buffer[0];
        C[c_cp + 1] ^= Buffer[1];
        C[c_cp + 2] ^= Buffer[4] ^ Buffer[0];
        MUL64_NO_SIMD_GF2X_XOR(Buffer, 5, A[a_cp + 2] ^ A[a_cp + 3], B[b_cp + 2] ^ B[b_cp + 3]);//x4, x5
        /* (A1+A2)*(B1+B2) */
        MUL64_NO_SIMD_GF2X_XOR(Buffer, 7, A[a_cp + 3] ^ A[a_cp + 4], B[b_cp + 3] ^ B[b_cp + 4]);//x6, x7
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(Buffer, 6, A[a_cp + 2] ^ A[a_cp + 4], B[b_cp + 2] ^ B[b_cp + 4]);//x2,x3
        C[c_cp + 3] ^= Buffer[5] ^ Buffer[1];
        C[c_cp + 4] ^= Buffer[4] ^ Buffer[6];
        C[c_cp + 5] ^= Buffer[5] ^ Buffer[7];
        C[c_cp + 6] ^= Buffer[6] ^ Buffer[8];
        C[c_cp + 7] ^= Buffer[7];
        C[c_cp + 8] ^= Buffer[8];
        long AA0 = A[a_cp] ^ A[a_cp + 2];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 3];
        long BB0 = B[b_cp] ^ B[b_cp + 2];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 3];
        MUL64_NO_SIMD_GF2X(Buffer, 0, AA0, BB0); //x0,x1
        MUL64_NO_SIMD_GF2X(Buffer, 2, AA1, BB1);//x2,x3
        Buffer[2] ^= Buffer[1];//x1+x2
        Buffer[3] ^= MUL32_NO_SIMD_GF2X(A[a_cp + 4], B[b_cp + 4]);//x3+x4
        C[c_cp + 2] ^= Buffer[0];
        C[c_cp + 3] ^= Buffer[2] ^ Buffer[0];//x0+x1+x2
        Buffer[2] ^= Buffer[3];//x1+x2+x3+x4
        C[c_cp + 4] ^= Buffer[2] ^ Buffer[0];//x0+x1+x2+x3+x4
        C[c_cp + 5] ^= Buffer[2];
        C[c_cp + 6] ^= Buffer[3];
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 3, AA0 ^ AA1, BB0 ^ BB1);//x4, x5
        /* (A1+A2)*(B1+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 5, AA1 ^ A[a_cp + 4], BB1 ^ B[b_cp + 4]);//x6, x7
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, c_cp + 4, AA0 ^ A[a_cp + 4], BB0 ^ B[b_cp + 4]);//x2,x3
    }

    private static void mul384_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] Buffer)
    {
        mul192_no_simd_gf2x(C, 0, A, a_cp, B, b_cp);
        mul192_no_simd_gf2x(C, 6, A, a_cp + 3, B, b_cp + 3);
        long AA0 = A[a_cp] ^ A[a_cp + 3];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 4];
        long AA2 = A[a_cp + 2] ^ A[a_cp + 5];
        long BB0 = B[b_cp] ^ B[b_cp + 3];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 4];
        long BB2 = B[b_cp + 2] ^ B[b_cp + 5];
        C[6] ^= C[3];
        C[7] ^= C[4];
        C[8] ^= C[5];
        MUL64_NO_SIMD_GF2X(Buffer, 0, AA0, BB0);//x0, x1
        /* A2*B2 */
        MUL64_NO_SIMD_GF2X(Buffer, 4, AA2, BB2);//x4,x5
        /* A1*B1 */
        MUL64_NO_SIMD_GF2X(Buffer, 2, AA1, BB1);//x2, x3
        C[3] = C[6] ^ C[0] ^ Buffer[0];
        Buffer[1] ^= Buffer[2];//C1=x1^x2
        Buffer[0] ^= Buffer[1];
        Buffer[3] ^= Buffer[4];//c3=x3^x4
        Buffer[4] = Buffer[3] ^ Buffer[5];//c4=x3+x4+x5
        C[5] = C[8] ^ C[2] ^ Buffer[3] ^ Buffer[0];//c2=x1+x2+x3+x4
        C[6] ^= C[9] ^ Buffer[1] ^ Buffer[4];//c3=x1+x2+x4+x5
        C[4] = C[7] ^ C[1] ^ Buffer[0];
        C[7] ^= C[10] ^ Buffer[4];
        C[8] ^= C[11] ^ Buffer[5];
        MUL64_NO_SIMD_GF2X_XOR(C, 4, AA0 ^ AA1, BB0 ^ BB1);//x6, x7
        /* (A1+A2)*(B1+B2)  */
        MUL64_NO_SIMD_GF2X_XOR(C, 6, AA1 ^ AA2, BB1 ^ BB2);//x10, x11
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, 5, AA0 ^ AA2, BB0 ^ BB2);//x8, x9
    }

    private static void mul384_no_simd_gf2x_xor(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] Buffer)
    {
        mul192_no_simd_gf2x(Buffer, 0, A, a_cp, B, b_cp);
        mul192_no_simd_gf2x(Buffer, 6, A, a_cp + 3, B, b_cp + 3);
        long AA0 = A[a_cp] ^ A[a_cp + 3];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 4];
        long AA2 = A[a_cp + 2] ^ A[a_cp + 5];
        long BB0 = B[b_cp] ^ B[b_cp + 3];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 4];
        long BB2 = B[b_cp + 2] ^ B[b_cp + 5];
        Buffer[6] ^= Buffer[3];
        Buffer[7] ^= Buffer[4];
        Buffer[8] ^= Buffer[5];
        C[0] ^= Buffer[0];
        C[1] ^= Buffer[1];
        C[2] ^= Buffer[2];
        C[3] ^= Buffer[6] ^ Buffer[0];
        C[5] ^= Buffer[8] ^ Buffer[2];
        C[6] ^= Buffer[6] ^ Buffer[9];
        C[4] ^= Buffer[7] ^ Buffer[1];
        C[7] ^= Buffer[7] ^ Buffer[10];
        C[8] ^= Buffer[8] ^ Buffer[11];
        C[9] ^= Buffer[9];
        C[10] ^= Buffer[10];
        C[11] ^= Buffer[11];
        MUL64_NO_SIMD_GF2X(Buffer, 0, AA0, BB0);//x0, x1
        /* A2*B2 */
        MUL64_NO_SIMD_GF2X(Buffer, 4, AA2, BB2);//x4,x5
        /* A1*B1 */
        MUL64_NO_SIMD_GF2X(Buffer, 2, AA1, BB1);//x2, x3
        C[3] ^= Buffer[0];
        Buffer[1] ^= Buffer[2];//C1=x1^x2
        Buffer[0] ^= Buffer[1];
        Buffer[3] ^= Buffer[4];//c3=x3^x4
        Buffer[4] = Buffer[3] ^ Buffer[5];//c4=x3+x4+x5
        C[5] ^= Buffer[3] ^ Buffer[0];//c2=x1+x2+x3+x4
        C[6] ^= Buffer[1] ^ Buffer[4];//c3=x1+x2+x4+x5
        C[4] ^= Buffer[0];
        C[7] ^= Buffer[4];
        C[8] ^= Buffer[5];
        MUL64_NO_SIMD_GF2X_XOR(C, 4, AA0 ^ AA1, BB0 ^ BB1);//x6, x7
        /* (A1+A2)*(B1+B2)  */
        MUL64_NO_SIMD_GF2X_XOR(C, 6, AA1 ^ AA2, BB1 ^ BB2);//x10, x11
        /* (A0+A2)*(B0+B2) */
        MUL64_NO_SIMD_GF2X_XOR(C, 5, AA0 ^ AA2, BB0 ^ BB2);//x8, x9
    }

    private static void mul416_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] RESERVED_BUF)
    {
        mul192_no_simd_gf2x(C, 0, A, a_cp, B, b_cp);
        mul128_no_simd_gf2x(C, 6, A[a_cp + 3], A[a_cp + 4], B[b_cp + 3], B[b_cp + 4]);
        MUL64_NO_SIMD_GF2X(C, 10, A[a_cp + 5], B[b_cp + 5]);
        C[12] = MUL32_NO_SIMD_GF2X(A[a_cp + 6], B[b_cp + 6]) ^ C[11];
        C[11] = C[10] ^ C[12];
        MUL64_NO_SIMD_GF2X_XOR(C, 11, A[a_cp + 5] ^ A[a_cp + 6], B[b_cp + 5] ^ B[b_cp + 6]);
        C[8] ^= C[10];
        C[11] ^= C[9];
        C[10] = C[8] ^ C[12];
        C[8] ^= C[6];
        C[9] = C[11] ^ C[7];
        mul128_no_simd_gf2x_xor(C, 8, A[a_cp + 3] ^ A[a_cp + 5], A[a_cp + 4] ^ A[a_cp + 6],
            B[b_cp + 3] ^ B[b_cp + 5], B[b_cp + 4] ^ B[b_cp + 6], RESERVED_BUF);
        long AA0 = A[a_cp] ^ A[a_cp + 3];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 4];
        long AA2 = A[a_cp + 2] ^ A[a_cp + 5];
        long AA3 = A[a_cp + 6];
        long BB0 = B[b_cp] ^ B[b_cp + 3];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 4];
        long BB2 = B[b_cp + 2] ^ B[b_cp + 5];
        long BB3 = B[b_cp + 6];
        C[6] ^= C[3];
        C[7] ^= C[4];
        C[8] ^= C[5];
        mul128_no_simd_gf2x(RESERVED_BUF, 0, AA0, AA1, BB0, BB1);
        MUL64_NO_SIMD_GF2X(RESERVED_BUF, 4, AA2, BB2);
        RESERVED_BUF[6] = MUL32_NO_SIMD_GF2X(AA3, BB3) ^ RESERVED_BUF[5];
        RESERVED_BUF[5] = RESERVED_BUF[4] ^ RESERVED_BUF[6];
        MUL64_NO_SIMD_GF2X_XOR(RESERVED_BUF, 5, AA2 ^ AA3, BB2 ^ BB3);
        C[3] = C[6] ^ C[0] ^ RESERVED_BUF[0];
        C[4] = C[7] ^ C[1] ^ RESERVED_BUF[1];
        RESERVED_BUF[2] ^= RESERVED_BUF[4];
        RESERVED_BUF[3] ^= RESERVED_BUF[5];
        C[5] = C[8] ^ C[2] ^ RESERVED_BUF[2] ^ RESERVED_BUF[0];
        C[6] ^= C[9] ^ RESERVED_BUF[3] ^ RESERVED_BUF[1];
        C[7] ^= C[10] ^ RESERVED_BUF[2] ^ RESERVED_BUF[6];
        C[8] ^= C[11] ^ RESERVED_BUF[3];
        C[9] ^= C[12] ^ RESERVED_BUF[6];
        mul128_no_simd_gf2x_xor(C, 5, AA0 ^ AA2, AA1 ^ AA3, BB0 ^ BB2, BB1 ^ BB3, RESERVED_BUF);
    }

    private static void mul416_no_simd_gf2x_xor(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] Buffer, long[] Buffer2)
    {
        mul192_no_simd_gf2x(Buffer, 0, A, a_cp, B, b_cp);
        mul128_no_simd_gf2x(Buffer, 6, A[a_cp + 3], A[a_cp + 4], B[b_cp + 3], B[b_cp + 4]);
        MUL64_NO_SIMD_GF2X(Buffer, 10, A[a_cp + 5], B[b_cp + 5]);
        Buffer[12] = MUL32_NO_SIMD_GF2X(A[a_cp + 6], B[b_cp + 6]) ^ Buffer[11];
        Buffer[11] = Buffer[10] ^ Buffer[12];
        MUL64_NO_SIMD_GF2X_XOR(Buffer, 11, A[a_cp + 5] ^ A[a_cp + 6], B[b_cp + 5] ^ B[b_cp + 6]);
        Buffer[8] ^= Buffer[10];
        Buffer[11] ^= Buffer[9];
        Buffer[10] = Buffer[8] ^ Buffer[12];
        Buffer[8] ^= Buffer[6];
        Buffer[9] = Buffer[11] ^ Buffer[7];
        Buffer[6] ^= Buffer[3];
        Buffer[7] ^= Buffer[4];
        Buffer[8] ^= Buffer[5];
        mul128_no_simd_gf2x_xor(Buffer, 8, A[a_cp + 3] ^ A[a_cp + 5], A[a_cp + 4] ^ A[a_cp + 6],
            B[b_cp + 3] ^ B[b_cp + 5], B[b_cp + 4] ^ B[b_cp + 6], Buffer2);
        C[0] ^= Buffer[0];
        C[1] ^= Buffer[1];
        C[2] ^= Buffer[2];
        C[3] ^= Buffer[6] ^ Buffer[0];
        C[4] ^= Buffer[7] ^ Buffer[1];
        C[5] ^= Buffer[8] ^ Buffer[2];
        C[6] ^= Buffer[6] ^ Buffer[9];
        C[7] ^= Buffer[7] ^ Buffer[10];
        C[8] ^= Buffer[8] ^ Buffer[11];
        C[9] ^= Buffer[9] ^ Buffer[12];
        C[10] ^= Buffer[10];
        C[11] ^= Buffer[11];
        C[12] ^= Buffer[12];
        long AA0 = A[a_cp] ^ A[a_cp + 3];
        long AA1 = A[a_cp + 1] ^ A[a_cp + 4];
        long AA2 = A[a_cp + 2] ^ A[a_cp + 5];
        long AA3 = A[a_cp + 6];
        long BB0 = B[b_cp] ^ B[b_cp + 3];
        long BB1 = B[b_cp + 1] ^ B[b_cp + 4];
        long BB2 = B[b_cp + 2] ^ B[b_cp + 5];
        long BB3 = B[b_cp + 6];
        mul128_no_simd_gf2x(Buffer, 0, AA0, AA1, BB0, BB1);
        MUL64_NO_SIMD_GF2X(Buffer, 4, AA2, BB2);
        Buffer[6] = MUL32_NO_SIMD_GF2X(AA3, BB3) ^ Buffer[5];
        Buffer[5] = Buffer[4] ^ Buffer[6];
        MUL64_NO_SIMD_GF2X_XOR(Buffer, 5, AA2 ^ AA3, BB2 ^ BB3);
        C[3] ^= Buffer[0];
        C[4] ^= Buffer[1];
        Buffer[2] ^= Buffer[4];
        Buffer[3] ^= Buffer[5];
        C[5] ^= Buffer[2] ^ Buffer[0];
        C[6] ^= Buffer[3] ^ Buffer[1];
        C[7] ^= Buffer[2] ^ Buffer[6];
        C[8] ^= Buffer[3];
        C[9] ^= Buffer[6];
        mul128_no_simd_gf2x_xor(C, 5, AA0 ^ AA2, AA1 ^ AA3, BB0 ^ BB2, BB1 ^ BB3, Buffer);
    }

    private static void mul544_no_simd_gf2x(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] AA, long[] BB,
                                            long[] RESERVED_BUF9)
    {
        mul128_no_simd_gf2x(C, 0, A[a_cp], A[a_cp + 1], B[b_cp], B[b_cp + 1]);
        mul128_no_simd_gf2x(C, 4, A[a_cp + 2], A[a_cp + 3], B[b_cp + 2], B[b_cp + 3]);
        C[4] ^= C[2];
        C[5] ^= C[3];
        C[2] = C[4] ^ C[0];
        C[3] = C[5] ^ C[1];
        C[4] ^= C[6];
        C[5] ^= C[7];
        mul128_no_simd_gf2x_xor(C, 2, A[a_cp] ^ A[a_cp + 2], A[a_cp + 1] ^ A[a_cp + 3],
            B[b_cp] ^ B[b_cp + 2], B[b_cp + 1] ^ B[b_cp + 3], RESERVED_BUF9);
        mul288_no_simd_gf2x(C, 8, A, a_cp + 4, B, b_cp + 4, RESERVED_BUF9);
        C[8] ^= C[4];
        C[9] ^= C[5];
        C[10] ^= C[6];
        C[11] ^= C[7];
        C[4] = C[8] ^ C[0];
        C[5] = C[9] ^ C[1];
        C[6] = C[10] ^ C[2];
        C[7] = C[11] ^ C[3];
        C[8] ^= C[12];
        C[9] ^= C[13];
        C[10] ^= C[14];
        C[11] ^= C[15];
        C[12] ^= C[16];
        AA[0] = A[a_cp] ^ A[a_cp + 4];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 5];
        AA[2] = A[a_cp + 2] ^ A[a_cp + 6];
        AA[3] = A[a_cp + 3] ^ A[a_cp + 7];
        AA[4] = A[a_cp + 8];
        BB[0] = B[b_cp] ^ B[b_cp + 4];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 5];
        BB[2] = B[b_cp + 2] ^ B[b_cp + 6];
        BB[3] = B[b_cp + 3] ^ B[b_cp + 7];
        BB[4] = B[b_cp + 8];
        mul288_no_simd_gf2x_xor(C, 4, AA, 0, BB, 0, RESERVED_BUF9);
    }

    private static void mul544_no_simd_gf2x_xor(long[] C, long[] A, int a_cp, long[] B, int b_cp, long[] AA, long[] BB,
                                                long[] Buffer, long[] Buffer2)
    {
        mul128_no_simd_gf2x(Buffer, 0, A[a_cp], A[a_cp + 1], B[b_cp], B[b_cp + 1]);
        mul128_no_simd_gf2x(Buffer, 4, A[a_cp + 2], A[a_cp + 3], B[b_cp + 2], B[b_cp + 3]);
        Buffer[4] ^= Buffer[2];
        Buffer[5] ^= Buffer[3];
        Buffer[2] = Buffer[4] ^ Buffer[0];
        Buffer[3] = Buffer[5] ^ Buffer[1];
        Buffer[4] ^= Buffer[6];
        Buffer[5] ^= Buffer[7];
        mul128_no_simd_gf2x_xor(Buffer, 2, A[a_cp] ^ A[a_cp + 2], A[a_cp + 1] ^ A[a_cp + 3],
            B[b_cp] ^ B[b_cp + 2], B[b_cp + 1] ^ B[b_cp + 3], Buffer2);
        mul288_no_simd_gf2x(Buffer, 8, A, a_cp + 4, B, b_cp + 4, Buffer2);
        Buffer[8] ^= Buffer[4];
        Buffer[9] ^= Buffer[5];
        Buffer[10] ^= Buffer[6];
        Buffer[11] ^= Buffer[7];
        C[0] ^= Buffer[0];
        C[1] ^= Buffer[1];
        C[2] ^= Buffer[2];
        C[3] ^= Buffer[3];
        C[4] ^= Buffer[8] ^ Buffer[0];
        C[5] ^= Buffer[9] ^ Buffer[1];
        C[6] ^= Buffer[10] ^ Buffer[2];
        C[7] ^= Buffer[11] ^ Buffer[3];
        C[8] ^= Buffer[8] ^ Buffer[12];
        C[9] ^= Buffer[9] ^ Buffer[13];
        C[10] ^= Buffer[10] ^ Buffer[14];
        C[11] ^= Buffer[11] ^ Buffer[15];
        C[12] ^= Buffer[12] ^ Buffer[16];
        C[13] ^= Buffer[13];
        C[14] ^= Buffer[14];
        C[15] ^= Buffer[15];
        C[16] ^= Buffer[16];
        AA[0] = A[a_cp] ^ A[a_cp + 4];
        AA[1] = A[a_cp + 1] ^ A[a_cp + 5];
        AA[2] = A[a_cp + 2] ^ A[a_cp + 6];
        AA[3] = A[a_cp + 3] ^ A[a_cp + 7];
        AA[4] = A[a_cp + 8];
        BB[0] = B[b_cp] ^ B[b_cp + 4];
        BB[1] = B[b_cp + 1] ^ B[b_cp + 5];
        BB[2] = B[b_cp + 2] ^ B[b_cp + 6];
        BB[3] = B[b_cp + 3] ^ B[b_cp + 7];
        BB[4] = B[b_cp + 8];
        mul288_no_simd_gf2x_xor(C, 4, AA, 0, BB, 0, Buffer);
    }
}
