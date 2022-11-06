package org.bouncycastle.pqc.crypto.gemss;

public class Rem_GF2n
{

    static void REM192_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[2] >>> ki) ^ (Pol[3] << ki64);
        Q[1] = (Pol[3] >>> ki) ^ (Pol[4] << ki64);
        Q[2] = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
        P[p_cp + 1] = Pol[1] ^ Q[1] ^ (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] = (Pol[2] ^ Q[2] ^ (Q[1] >>> k364) ^ (Q[2] << k3)) & mask;
        long R = Q[0] ^ ((ki >= k3) ? Q[2] >>> (ki - k3) : (Q[1] >>> (k364 + ki)) ^ (Q[2] << (k3 - ki)));
        P[p_cp] = Pol[0] ^ R ^ (R << k3);
    }

//    static void REM288_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
//    {
//        Q[0] = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
//        Q[1] = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
//        Q[2] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
//        Q[3] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
//        Q[4] = Pol[8] >>> ki;
//        P[p_cp] = Pol[0] ^ Q[0] ^ (Q[0] << k3);
//        P[p_cp + 1] = Pol[1] ^ Q[1] ^ (Q[0] >>> k364) ^ (Q[1] << k3);
//        P[p_cp + 2] = Pol[2] ^ Q[2] ^ (Q[1] >>> k364) ^ (Q[2] << k3);
//        P[p_cp + 3] = Pol[3] ^ Q[3] ^ (Q[2] >>> k364) ^ (Q[3] << k3);
//        P[p_cp + 4] = Pol[4] ^ Q[4] ^ (Q[3] >>> k364) ^ (Q[4] << k3);
//        long R = (ki >= k3) ? Q[4] >>> (ki - k3) : (Q[3] >>> (k364 + ki)) ^ (Q[4] << (k3 - ki));
//        P[p_cp] ^= R ^ (R << k3);
//        P[p_cp + 4] &= mask;
//    }

    static void REM288_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
        Q[1] = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
        Q[2] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        Q[3] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[4] = (Pol[8] >>> ki);
        P[p_cp + 2] = Pol[2] ^ Q[2] ^ (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 3] = Pol[3] ^ Q[3] ^ (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 4] = (Pol[4] ^ Q[4] ^ (Q[3] >>> k364) ^ (Q[4] << k3)) & mask;
        long R = Q[0] ^ ((ki >= k3) ? Q[4] >>> (ki - k3) : (Q[3] >>> (k364 + ki)) ^ (Q[4] << (k3 - ki)));
        P[p_cp] = Pol[0] ^ R ^ (R << k3);
        P[p_cp + 1] = Pol[1] ^ Q[1] ^ (Q[1] << k3) ^ (R >>> k364);
    }

    static void REM544_PENTANOMIAL_K3_IS_128_GF2X(long[] P, int p_cp, long[] Pol, int k1, int k2, int ki, int ki64,
                                           int k164, int k264, long[] Q, long mask)
    {
        Q[2] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        Q[3] = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        Q[4] = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
        Q[5] = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
        Q[6] = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
        Q[7] = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
        Q[8] = (Pol[16] >>> ki);
        Q[0] = (Pol[8] >>> ki) ^ (Pol[9] << ki64) ^ (Pol[16] >>> (k264)) ^ (Q[6] >>> ki) ^ (Q[7] << ki64);
        Q[1] = (Pol[9] >>> ki) ^ (Pol[10] << ki64) ^ (Q[7] >>> ki) ^ (Q[8] << ki64);
        P[p_cp] = Pol[0] ^ Q[0] ^ (Q[0] << k1) ^ (Q[0] << k2);
        P[p_cp + 1] = Pol[1] ^ Q[1] ^ (Q[0] >>> k164) ^ (Q[1] << k1) ^ (Q[0] >>> k264) ^ (Q[1] << k2);
        P[p_cp + 2] = Pol[2] ^ Q[2] ^ Q[0] ^ (Q[1] >>> k164) ^ (Q[2] << k1) ^ (Q[1] >>> k264) ^ (Q[2] << k2);
        P[p_cp + 3] = Pol[3] ^ Q[3] ^ Q[1] ^ (Q[2] >>> k164) ^ (Q[3] << k1) ^ (Q[2] >>> k264) ^ (Q[3] << k2);
        P[p_cp + 4] = Pol[4] ^ Q[4] ^ Q[2] ^ (Q[3] >>> k164) ^ (Q[4] << k1) ^ (Q[3] >>> k264) ^ (Q[4] << k2);
        P[p_cp + 5] = Pol[5] ^ Q[5] ^ Q[3] ^ (Q[4] >>> k164) ^ (Q[5] << k1) ^ (Q[4] >>> k264) ^ (Q[5] << k2);
        P[p_cp + 6] = Pol[6] ^ Q[6] ^ Q[4] ^ (Q[5] >>> k164) ^ (Q[6] << k1) ^ (Q[5] >>> k264) ^ (Q[6] << k2);
        P[p_cp + 7] = Pol[7] ^ Q[7] ^ Q[5] ^ (Q[6] >>> k164) ^ (Q[7] << k1) ^ (Q[6] >>> k264) ^ (Q[7] << k2);
        P[p_cp + 8] = (Pol[8] ^ Q[8] ^ Q[6] ^ (Q[7] >>> k164) ^ (Q[8] << k1) ^ (Q[7] >>> k264) ^ (Q[8] << k2)) & mask;
    }

    static void REM544_PENTANOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k1, int k2, int k3, int ki, int ki64, int k164,
                                 int k264, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[1] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[2] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        Q[3] = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        Q[4] = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
        Q[5] = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
        Q[6] = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
        Q[7] = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
        Q[8] = Pol[16] >>> ki;
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp + 5] = Pol[5] ^ Q[5];
        P[p_cp + 6] = Pol[6] ^ Q[6];
        P[p_cp + 7] = Pol[7] ^ Q[7];
        P[p_cp + 8] = Pol[8] ^ Q[8];
        P[p_cp] ^= Q[0] << k1;
        P[p_cp + 1] ^= (Q[0] >>> k164) ^ (Q[1] << k1);
        P[p_cp + 2] ^= (Q[1] >>> k164) ^ (Q[2] << k1);
        P[p_cp + 3] ^= (Q[2] >>> k164) ^ (Q[3] << k1);
        P[p_cp + 4] ^= (Q[3] >>> k164) ^ (Q[4] << k1);
        P[p_cp + 5] ^= (Q[4] >>> k164) ^ (Q[5] << k1);
        P[p_cp + 6] ^= (Q[5] >>> k164) ^ (Q[6] << k1);
        P[p_cp + 7] ^= (Q[6] >>> k164) ^ (Q[7] << k1);
        P[p_cp + 8] ^= (Q[7] >>> k164) ^ (Q[8] << k1);
        P[p_cp] ^= Q[0] << k2;
        P[p_cp + 1] ^= (Q[0] >>> k264) ^ (Q[1] << k2);
        P[p_cp + 2] ^= (Q[1] >>> k264) ^ (Q[2] << k2);
        P[p_cp + 3] ^= (Q[2] >>> k264) ^ (Q[3] << k2);
        P[p_cp + 4] ^= (Q[3] >>> k264) ^ (Q[4] << k2);
        P[p_cp + 5] ^= (Q[4] >>> k264) ^ (Q[5] << k2);
        P[p_cp + 6] ^= (Q[5] >>> k264) ^ (Q[6] << k2);
        P[p_cp + 7] ^= (Q[6] >>> k264) ^ (Q[7] << k2);
        P[p_cp + 8] ^= (Q[7] >>> k264) ^ (Q[8] << k2);
        P[p_cp] ^= Q[0] << k3;
        P[p_cp + 1] ^= (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] ^= (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 3] ^= (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 4] ^= (Q[3] >>> k364) ^ (Q[4] << k3);
        P[p_cp + 5] ^= (Q[4] >>> k364) ^ (Q[5] << k3);
        P[p_cp + 6] ^= (Q[5] >>> k364) ^ (Q[6] << k3);
        P[p_cp + 7] ^= (Q[6] >>> k364) ^ (Q[7] << k3);
        P[p_cp + 8] ^= (Q[7] >>> k364) ^ (Q[8] << k3);
        /* 64-(k364+ki) == (k3-ki) */
        long R = (ki >= k3) ? Q[8] >>> (ki - k3) : (Q[7] >>> (k364 + ki)) ^ (Q[8] << (k3 - ki));
        R ^= (ki >= k2) ? Q[8] >>> (ki - k2) : (Q[7] >>> (k264 + ki)) ^ (Q[8] << (k2 - ki));
        R ^= (ki >= k1) ? Q[8] >>> (ki - k1) : (Q[7] >>> (k164 + ki)) ^ (Q[8] << (k1 - ki));
        P[p_cp] ^= R;
        P[p_cp] ^= R << k1;
        P[p_cp] ^= R << k2;
        P[p_cp] ^= R << k3;
        P[p_cp + 8] &= mask;
    }

    static void REM384_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[2] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[3] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[4] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[5] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        Q[0] = (Pol[5] >>> ki) ^ (Pol[6] << ki64) ^ (Q[3] >>> (k364 + ki)) ^ (Q[4] << (k3 - ki));
        Q[1] = (Pol[6] >>> ki) ^ (Pol[7] << ki64) ^ (Q[4] >>> (k364 + ki)) ^ (Q[5] << (k3 - ki));
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1] ^ (Q[0] << k3);
        P[p_cp + 2] = Pol[2] ^ Q[2] ^ (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 3] = Pol[3] ^ Q[3] ^ (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 4] = Pol[4] ^ Q[4] ^ (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 5] = (Pol[5] ^ Q[5] ^ (Q[3] >>> k364)) & mask;
    }

    static void REM384_SPECIALIZED358_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[1] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        Q[2] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[3] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[4] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[5] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        Q[0] = (Pol[5] >>> ki) ^ (Pol[6] << ki64) ^ (Q[4] >>> (k364 + ki)) ^ (Q[5] << (k3 - ki));
        /* 64-(k364+ki) == (k3-ki) */
        P[p_cp] = Pol[0] ^ Q[0] ^ (Q[0] << k3);
        P[p_cp + 1] = Pol[1] ^ Q[1] ^ (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] = Pol[2] ^ Q[2] ^ (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 3] = Pol[3] ^ Q[3] ^ (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 4] = Pol[4] ^ Q[4] ^ (Q[3] >>> k364) ^ (Q[4] << k3);
        P[p_cp + 5] = (Pol[5] ^ Q[5] ^ (Q[4] >>> k364)) & mask;
    }

    static void REM384_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = ((Pol)[5] >>> ki) ^ ((Pol)[6] << ki64);
        Q[1] = ((Pol)[6] >>> ki) ^ ((Pol)[7] << ki64);
        Q[2] = ((Pol)[7] >>> ki) ^ ((Pol)[8] << ki64);
        Q[3] = ((Pol)[8] >>> ki) ^ ((Pol)[9] << ki64);
        Q[4] = ((Pol)[9] >>> ki) ^ ((Pol)[10] << ki64);
        Q[5] = ((Pol)[10] >>> ki) ^ ((Pol)[11] << ki64);
        long R = Q[0] ^ ((ki >= k3) ? Q[5] >>> (ki - k3) : (Q[4] >>> (k364 + ki)) ^ (Q[5] << (k3 - ki)));
        P[p_cp] = Pol[0] ^ R ^ (R << k3);
        P[p_cp + 1] = Pol[1] ^ Q[1] ^ (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 2] = Pol[2] ^ Q[2] ^ (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 3] = Pol[3] ^ Q[3] ^ (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 4] = Pol[4] ^ Q[4] ^ (Q[3] >>> k364) ^ (Q[4] << k3);
        P[p_cp + 5] = (Pol[5] ^ Q[5] ^ (Q[4] >>> k364) ^ (Q[5] << k3)) & mask;
    }

    static void REM402_SPECIALIZED_TRINOMIAL_GF2X(long[] P, int p_cp, long[] Pol, int k3, int ki, int ki64, int k364, long[] Q, long mask)
    {
        Q[0] = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
        Q[1] = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
        Q[2] = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
        Q[3] = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
        Q[4] = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
        Q[5] = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
        Q[6] = (Pol[12] >>> ki);

        Q[0] ^= (Q[3] >>> 39) ^ (Q[4] << 25);
        Q[1] ^= (Q[4] >>> 39) ^ (Q[5] << 25);
        Q[2] ^= (Q[5] >>> 39) ^ (Q[6] << 25);
        P[p_cp] = Pol[0] ^ Q[0];
        P[p_cp + 1] = Pol[1] ^ Q[1];
        P[p_cp + 2] = Pol[2] ^ Q[2];
        P[p_cp + 3] = Pol[3] ^ Q[3];
        P[p_cp + 4] = Pol[4] ^ Q[4];
        P[p_cp + 5] = Pol[5] ^ Q[5];
        P[p_cp + 6] = Pol[6] ^ Q[6];

        P[p_cp + 2] ^= (Q[0] << k3);
        P[p_cp + 3] ^= (Q[0] >>> k364) ^ (Q[1] << k3);
        P[p_cp + 4] ^= (Q[1] >>> k364) ^ (Q[2] << k3);
        P[p_cp + 5] ^= (Q[2] >>> k364) ^ (Q[3] << k3);
        P[p_cp + 6] ^= Q[3] >>> k364;
        P[p_cp + 6] &= mask;
    }
}
