package org.bouncycastle.pqc.crypto.gemss;

class Sqr_GF2n
{
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

    static void SQR192_NO_SIMD_GF2X(long[] C, long[] A, int a_cp)
    {
        SQR64_NO_SIMD_GF2X(C, 4, A[a_cp + 2]);
        SQR128_NO_SIMD_GF2X(C, 0, A, a_cp);
    }

    private static void SQR256_NO_SIMD_GF2X(long[] C, int c_cp, long[] A, int a_cp)
    {
        SQR128_NO_SIMD_GF2X(C, c_cp + 4, A, a_cp + 2);
        SQR128_NO_SIMD_GF2X(C, c_cp, A, a_cp);
    }

    static void SQR288_NO_SIMD_GF2X(long[] C, long[] A, int a_cp)
    {
        C[8] = SQR32_NO_SIMD_GF2X(A[a_cp + 4]);
        SQR256_NO_SIMD_GF2X(C, 0, A, a_cp);
    }

    static void SQR384_NO_SIMD_GF2X(long[] C, long[] A, int a_cp)
    {
        SQR128_NO_SIMD_GF2X(C, 8, A, a_cp + 4);
        SQR256_NO_SIMD_GF2X(C, 0, A, a_cp);
    }

    static void SQR416_NO_SIMD_GF2X(long[] C, long[] A, int a_cp)
    {
        C[12] = SQR32_NO_SIMD_GF2X(A[a_cp + 2]);
        SQR128_NO_SIMD_GF2X(C, 8, A, a_cp);
        SQR256_NO_SIMD_GF2X(C, 0, A, a_cp);
    }

    static void SQR544_NO_SIMD_GF2X(long[] C, long[] A, int a_cp)
    {
        C[16] = SQR32_NO_SIMD_GF2X(A[a_cp + 8]);
        SQR256_NO_SIMD_GF2X(C, 8, A, a_cp + 4);
        SQR256_NO_SIMD_GF2X(C, 0, A, a_cp);
    }
}
