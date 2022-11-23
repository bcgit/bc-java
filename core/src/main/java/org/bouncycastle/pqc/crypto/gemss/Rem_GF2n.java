package org.bouncycastle.pqc.crypto.gemss;

class Rem_GF2n
{
    static void REM192_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        long Q0 = (Pol[2] >>> ki) ^ (Pol[3] << ki64);
        long Q1 = (Pol[3] >>> ki) ^ (Pol[4] << ki64);
        long Q2 = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
        P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k364) ^ (Q1 << k3);
        P[p_cp + 2] = (Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3)) & mask;
        long R = Q0 ^ ((ki >= k3) ? Q2 >>> (ki - k3) : (Q1 >>> (k364 + ki)) ^ (Q2 << (k3 - ki)));
        P[p_cp] = Pol[0] ^ R ^ (R << k3);
    }

    static void REM288_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        long Q0 = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
        long Q1 = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
        long Q2 = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        long Q3 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        long Q4 = (Pol[8] >>> ki);
        P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
        P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
        P[p_cp + 4] = (Pol[4] ^ Q4 ^ (Q3 >>> k364) ^ (Q4 << k3)) & mask;
        long R = Q0 ^ ((ki >= k3) ? Q4 >>> (ki - k3) : (Q3 >>> (k364 + ki)) ^ (Q4 << (k3 - ki)));
        P[p_cp] = Pol[0] ^ R ^ (R << k3);
        P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q1 << k3) ^ (R >>> k364);
    }

    static void REM544_PENTANOMIAL_K3_IS_128_GF2X(long[] P, int p_cp, long[] Pol, int k1, int k2, int ki, int ki64,
                                                  int k164, int k264, long[] Q, long mask)
    {
        long Q2 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        long Q3 = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        long Q4 = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
        long Q5 = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
        long Q6 = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
        long Q7 = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
        long Q8 = (Pol[16] >>> ki);
        long Q0 = (Pol[8] >>> ki) ^ (Pol[9] << ki64) ^ (Pol[16] >>> (k264)) ^ (Q6 >>> ki) ^ (Q7 << ki64);
        long Q1 = (Pol[9] >>> ki) ^ (Pol[10] << ki64) ^ (Q7 >>> ki) ^ (Q8 << ki64);
        P[p_cp] = Pol[0] ^ Q0 ^ (Q0 << k1) ^ (Q0 << k2);
        P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2);
        P[p_cp + 2] = Pol[2] ^ Q2 ^ Q0 ^ (Q1 >>> k164) ^ (Q2 << k1) ^ (Q1 >>> k264) ^ (Q2 << k2);
        P[p_cp + 3] = Pol[3] ^ Q3 ^ Q1 ^ (Q2 >>> k164) ^ (Q3 << k1) ^ (Q2 >>> k264) ^ (Q3 << k2);
        P[p_cp + 4] = Pol[4] ^ Q4 ^ Q2 ^ (Q3 >>> k164) ^ (Q4 << k1) ^ (Q3 >>> k264) ^ (Q4 << k2);
        P[p_cp + 5] = Pol[5] ^ Q5 ^ Q3 ^ (Q4 >>> k164) ^ (Q5 << k1) ^ (Q4 >>> k264) ^ (Q5 << k2);
        P[p_cp + 6] = Pol[6] ^ Q6 ^ Q4 ^ (Q5 >>> k164) ^ (Q6 << k1) ^ (Q5 >>> k264) ^ (Q6 << k2);
        P[p_cp + 7] = Pol[7] ^ Q7 ^ Q5 ^ (Q6 >>> k164) ^ (Q7 << k1) ^ (Q6 >>> k264) ^ (Q7 << k2);
        P[p_cp + 8] = (Pol[8] ^ Q8 ^ Q6 ^ (Q7 >>> k164) ^ (Q8 << k1) ^ (Q7 >>> k264) ^ (Q8 << k2)) & mask;
    }

    static void REM544_PENTANOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k1, int k2, int k3, int ki, int ki64, int k164,
                                        int k264, int k364, long[] Q, long mask)
    {
        long Q0 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        long Q1 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        long Q2 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        long Q3 = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        long Q4 = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
        long Q5 = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
        long Q6 = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
        long Q7 = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
        long Q8 = Pol[16] >>> ki;
        P[p_cp] = Pol[0] ^ Q0 ^ (Q0 << k1) ^ (Q0 << k2) ^ (Q0 << k3);
        P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
        P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q1 >>> k164) ^ (Q2 << k1) ^ (Q1 >>> k264) ^ (Q2 << k2) ^ (Q1 >>> k364) ^ (Q2 << k3);
        P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q2 >>> k164) ^ (Q3 << k1) ^ (Q2 >>> k264) ^ (Q3 << k2) ^ (Q2 >>> k364) ^ (Q3 << k3);
        P[p_cp + 4] = Pol[4] ^ Q4 ^ (Q3 >>> k164) ^ (Q4 << k1) ^ (Q3 >>> k264) ^ (Q4 << k2) ^ (Q3 >>> k364) ^ (Q4 << k3);
        P[p_cp + 5] = Pol[5] ^ Q5 ^ (Q4 >>> k164) ^ (Q5 << k1) ^ (Q4 >>> k264) ^ (Q5 << k2) ^ (Q4 >>> k364) ^ (Q5 << k3);
        P[p_cp + 6] = Pol[6] ^ Q6 ^ (Q5 >>> k164) ^ (Q6 << k1) ^ (Q5 >>> k264) ^ (Q6 << k2) ^ (Q5 >>> k364) ^ (Q6 << k3);
        P[p_cp + 7] = Pol[7] ^ Q7 ^ (Q6 >>> k164) ^ (Q7 << k1) ^ (Q6 >>> k264) ^ (Q7 << k2) ^ (Q6 >>> k364) ^ (Q7 << k3);
        P[p_cp + 8] = (Pol[8] ^ Q8 ^ (Q7 >>> k164) ^ (Q8 << k1) ^ (Q7 >>> k264) ^ (Q8 << k2) ^ (Q7 >>> k364) ^ (Q8 << k3)) & mask;
        /* 64-(k364+ki) == (k3-ki) */
        long R = (ki >= k3) ? Q8 >>> (ki - k3) : (Q7 >>> (k364 + ki)) ^ (Q8 << (k3 - ki));
        R ^= (ki >= k2) ? Q8 >>> (ki - k2) : (Q7 >>> (k264 + ki)) ^ (Q8 << (k2 - ki));
        R ^= (ki >= k1) ? Q8 >>> (ki - k1) : (Q7 >>> (k164 + ki)) ^ (Q8 << (k1 - ki));
        P[p_cp] ^= R ^ (R << k1) ^ (R << k2) ^ (R << k3);
    }

    static void REM384_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        long Q2 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        long Q3 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        long Q4 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        long Q5 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        long Q0 = (Pol[5] >>> ki) ^ (Pol[6] << ki64) ^ (Q3 >>> (k364 + ki)) ^ (Q4 << (k3 - ki));
        long Q1 = (Pol[6] >>> ki) ^ (Pol[7] << ki64) ^ (Q4 >>> (k364 + ki)) ^ (Q5 << (k3 - ki));
        P[p_cp] = Pol[0] ^ Q0;
        P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 << k3);
        P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q0 >>> k364) ^ (Q1 << k3);
        P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q1 >>> k364) ^ (Q2 << k3);
        P[p_cp + 4] = Pol[4] ^ Q4 ^ (Q2 >>> k364) ^ (Q3 << k3);
        P[p_cp + 5] = (Pol[5] ^ Q5 ^ (Q3 >>> k364)) & mask;
    }

    static void REM384_SPECIALIZED358_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        long Q1 = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        long Q2 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        long Q3 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        long Q4 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        long Q5 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        long Q0 = (Pol[5] >>> ki) ^ (Pol[6] << ki64) ^ (Q4 >>> (k364 + ki)) ^ (Q5 << (k3 - ki));
        /* 64-(k364+ki) == (k3-ki) */
        P[p_cp] = Pol[0] ^ Q0 ^ (Q0 << k3);
        P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k364) ^ (Q1 << k3);
        P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
        P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
        P[p_cp + 4] = Pol[4] ^ Q4 ^ (Q3 >>> k364) ^ (Q4 << k3);
        P[p_cp + 5] = (Pol[5] ^ Q5 ^ (Q4 >>> k364)) & mask;
    }

    static void REM384_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        long Q0 = ((Pol)[5] >>> ki) ^ ((Pol)[6] << ki64);
        long Q1 = ((Pol)[6] >>> ki) ^ ((Pol)[7] << ki64);
        long Q2 = ((Pol)[7] >>> ki) ^ ((Pol)[8] << ki64);
        long Q3 = ((Pol)[8] >>> ki) ^ ((Pol)[9] << ki64);
        long Q4 = ((Pol)[9] >>> ki) ^ ((Pol)[10] << ki64);
        long Q5 = ((Pol)[10] >>> ki) ^ ((Pol)[11] << ki64);
        long R = Q0 ^ ((ki >= k3) ? Q5 >>> (ki - k3) : (Q4 >>> (k364 + ki)) ^ (Q5 << (k3 - ki)));
        P[p_cp] = Pol[0] ^ R ^ (R << k3);
        P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k364) ^ (Q1 << k3);
        P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
        P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
        P[p_cp + 4] = Pol[4] ^ Q4 ^ (Q3 >>> k364) ^ (Q4 << k3);
        P[p_cp + 5] = (Pol[5] ^ Q5 ^ (Q4 >>> k364) ^ (Q5 << k3)) & mask;
    }

    static void REM402_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        long Q3 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        long Q4 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        long Q5 = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        long Q6 = (Pol[12] >>> ki);
        long Q0 = (Q3 >>> 39) ^ (Q4 << 25) ^ (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        long Q1 = (Q4 >>> 39) ^ (Q5 << 25) ^ (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        long Q2 = (Q5 >>> 39) ^ (Q6 << 25) ^ (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        P[p_cp] = Pol[0] ^ Q0;
        P[p_cp + 1] = Pol[1] ^ Q1;
        P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q0 << k3);
        P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q0 >>> k364) ^ (Q1 << k3);
        P[p_cp + 4] = Pol[4] ^ Q4 ^ (Q1 >>> k364) ^ (Q2 << k3);
        P[p_cp + 5] = Pol[5] ^ Q5 ^ (Q2 >>> k364) ^ (Q3 << k3);
        P[p_cp + 6] = (Pol[6] ^ Q6 ^ (Q3 >>> k364)) & mask;
    }
}
