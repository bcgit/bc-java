package org.bouncycastle.pqc.crypto.gemss;

abstract class Rem_GF2n
{
    public abstract void rem_gf2n(long[] P, int p_cp, long[] Pol);

    public abstract void rem_gf2n_xor(long[] P, int p_cp, long[] Pol);

    protected long mask;
    protected int ki;
    protected int ki64;

    public static class REM192_SPECIALIZED_TRINOMIAL_GF2X
        extends Rem_GF2n
    {
        //gemss128, bluegemss128, redgemss128, whitegemss128, cyangemss128, magentagemss128
        private final int k3;
        private final int k364;
        private final int ki_k3;//(46, 13), (47, 16), (49, 8), (50, 31)

        REM192_SPECIALIZED_TRINOMIAL_GF2X(int k3, int ki, int ki64, int k364, long mask)
        {
            this.k3 = k3;
            this.ki = ki;
            this.ki64 = ki64;
            this.k364 = k364;
            this.mask = mask;
            ki_k3 = ki - k3;
        }

        public void rem_gf2n(long[] P, int p_cp, long[] Pol)
        {
            long Q0 = (Pol[2] >>> ki) ^ (Pol[3] << ki64);
            long Q1 = (Pol[3] >>> ki) ^ (Pol[4] << ki64);
            long Q2 = (Pol[4] >>> ki) ^ (Pol[5] << ki64);//min(ki64)=14
            P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 2] = (Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3)) & mask;
            Q0 ^= Q2 >>> ki_k3;
            P[p_cp] = Pol[0] ^ Q0 ^ (Q0 << k3);
        }

        public void rem_gf2n_xor(long[] P, int p_cp, long[] Pol)
        {
            long Q0 = (Pol[2] >>> ki) ^ (Pol[3] << ki64);
            long Q1 = (Pol[3] >>> ki) ^ (Pol[4] << ki64);
            long Q2 = (Pol[4] >>> ki) ^ (Pol[5] << ki64);
            P[p_cp + 1] ^= Pol[1] ^ Q1 ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 2] ^= (Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3)) & mask;
            Q0 ^= Q2 >>> ki_k3;
            P[p_cp] ^= Pol[0] ^ Q0 ^ (Q0 << k3);
        }
    }


    public static class REM288_SPECIALIZED_TRINOMIAL_GF2X
        extends Rem_GF2n
    {
        //gemss192, bluegemss192, redgemss192, whitegemss192, cyangemss192, magentagemss192, fgemss128, dualmodems128
        private final int k3;
        private final int k364;
        private final int k364ki;
        private final int k3_ki;

        public REM288_SPECIALIZED_TRINOMIAL_GF2X(int k3, int ki, int ki64, int k364, long mask)
        {
            this.k3 = k3;
            this.ki = ki;
            this.ki64 = ki64;
            this.k364 = k364;
            this.mask = mask;
            k364ki = k364 + ki;
            k3_ki = k3 - ki;
        }

        public void rem_gf2n(long[] P, int p_cp, long[] Pol)
        {
            long Q1 = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
            long Q2 = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
            P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
            long Q3 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
            long Q4 = (Pol[8] >>> ki);
            Q2 = (Pol[4] >>> ki) ^ (Pol[5] << ki64) ^ (Q3 >>> k364ki) ^ (Q4 << k3_ki);
            P[p_cp + 4] = (Pol[4] ^ Q4 ^ (Q3 >>> k364) ^ (Q4 << k3)) & mask;
            P[p_cp] = Pol[0] ^ Q2 ^ (Q2 << k3);
            P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q1 << k3) ^ (Q2 >>> k364);
        }

        public void rem_gf2n_xor(long[] P, int p_cp, long[] Pol)
        {
            long Q1 = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
            long Q2 = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
            P[p_cp + 2] ^= Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
            long Q3 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            P[p_cp + 3] ^= Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
            Q2 = Pol[8] >>> ki;
            P[p_cp + 4] ^= (Pol[4] ^ Q2 ^ (Q3 >>> k364) ^ (Q2 << k3)) & mask;
            Q3 = (Pol[4] >>> ki) ^ (Pol[5] << ki64) ^ (Q3 >>> k364ki) ^ (Q2 << k3_ki);
            P[p_cp] ^= Pol[0] ^ Q3 ^ (Q3 << k3);
            P[p_cp + 1] ^= Pol[1] ^ Q1 ^ (Q1 << k3) ^ (Q3 >>> k364);
        }
    }

    public static class REM544_PENTANOMIAL_K3_IS_128_GF2X
        extends Rem_GF2n
    {
        //dualmodems256
        private final int k1;
        private final int k2;
        private final int k164;
        private final int k264;

        public REM544_PENTANOMIAL_K3_IS_128_GF2X(int k1, int k2, int ki, int ki64, int k164, int k264, long mask)
        {
            this.k1 = k1;
            this.k2 = k2;
            this.ki = ki;
            this.ki64 = ki64;
            this.k164 = k164;
            this.k264 = k264;
            this.mask = mask;
        }

        public void rem_gf2n(long[] P, int p_cp, long[] Pol)
        {
            long Q2 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            long Q3 = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
            long Q1 = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
            P[p_cp + 4] = Pol[4] ^ Q1 ^ Q2 ^ (Q3 >>> k164) ^ (Q1 << k1) ^ (Q3 >>> k264) ^ (Q1 << k2);
            long Q5 = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
            P[p_cp + 5] = Pol[5] ^ Q5 ^ Q3 ^ (Q1 >>> k164) ^ (Q5 << k1) ^ (Q1 >>> k264) ^ (Q5 << k2);
            long Q0 = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
            P[p_cp + 6] = Pol[6] ^ Q0 ^ Q1 ^ (Q5 >>> k164) ^ (Q0 << k1) ^ (Q5 >>> k264) ^ (Q0 << k2);
            Q1 = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
            P[p_cp + 7] = Pol[7] ^ Q1 ^ Q5 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2);
            Q5 = Pol[16] >>> ki;
            P[p_cp + 8] = (Pol[8] ^ Q5 ^ Q0 ^ (Q1 >>> k164) ^ (Q5 << k1) ^ (Q1 >>> k264) ^ (Q5 << k2)) & mask;
            Q0 = ((Pol[8] ^ Q0) >>> ki) ^ ((Pol[9] ^ Q1) << ki64) ^ (Pol[16] >>> k264);
            Q1 = ((Pol[9] ^ Q1) >>> ki) ^ ((Pol[10] ^ Q5) << ki64);
            P[p_cp] = Pol[0] ^ Q0 ^ (Q0 << k1) ^ (Q0 << k2);
            P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2);
            P[p_cp + 2] = Pol[2] ^ Q2 ^ Q0 ^ (Q1 >>> k164) ^ (Q2 << k1) ^ (Q1 >>> k264) ^ (Q2 << k2);
            P[p_cp + 3] = Pol[3] ^ Q3 ^ Q1 ^ (Q2 >>> k164) ^ (Q3 << k1) ^ (Q2 >>> k264) ^ (Q3 << k2);
        }

        public void rem_gf2n_xor(long[] P, int p_cp, long[] Pol)
        {
            long Q2 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            long Q3 = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
            long Q1 = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
            P[p_cp + 4] ^= Pol[4] ^ Q1 ^ Q2 ^ (Q3 >>> k164) ^ (Q1 << k1) ^ (Q3 >>> k264) ^ (Q1 << k2);
            long Q5 = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
            P[p_cp + 5] ^= Pol[5] ^ Q5 ^ Q3 ^ (Q1 >>> k164) ^ (Q5 << k1) ^ (Q1 >>> k264) ^ (Q5 << k2);
            long Q0 = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
            P[p_cp + 6] ^= Pol[6] ^ Q0 ^ Q1 ^ (Q5 >>> k164) ^ (Q0 << k1) ^ (Q5 >>> k264) ^ (Q0 << k2);
            Q1 = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
            P[p_cp + 7] ^= Pol[7] ^ Q1 ^ Q5 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2);
            Q5 = Pol[16] >>> ki;
            P[p_cp + 8] ^= (Pol[8] ^ Q5 ^ Q0 ^ (Q1 >>> k164) ^ (Q5 << k1) ^ (Q1 >>> k264) ^ (Q5 << k2)) & mask;
            Q0 = ((Pol[8] ^ Q0) >>> ki) ^ ((Pol[9] ^ Q1) << ki64) ^ (Pol[16] >>> k264);
            Q1 = ((Pol[9] ^ Q1) >>> ki) ^ ((Pol[10] ^ Q5) << ki64);
            P[p_cp] ^= Pol[0] ^ Q0 ^ (Q0 << k1) ^ (Q0 << k2);
            P[p_cp + 1] ^= Pol[1] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2);
            P[p_cp + 2] ^= Pol[2] ^ Q2 ^ Q0 ^ (Q1 >>> k164) ^ (Q2 << k1) ^ (Q1 >>> k264) ^ (Q2 << k2);
            P[p_cp + 3] ^= Pol[3] ^ Q3 ^ Q1 ^ (Q2 >>> k164) ^ (Q3 << k1) ^ (Q2 >>> k264) ^ (Q3 << k2);
        }
    }


    public static class REM544_PENTANOMIAL_GF2X
        extends Rem_GF2n
    {
        //fgemss256
        private final int k1;
        private final int k2;
        private final int k3;
        private final int k164;
        private final int k264;
        private final int k364;
        private final int ki_k3;
        private final int ki_k2;
        private final int ki_k1;

        public REM544_PENTANOMIAL_GF2X(int k1, int k2, int k3, int ki, int ki64, int k164,
                                       int k264, int k364, long mask)
        {
            this.k1 = k1;
            this.k2 = k2;
            this.k3 = k3;
            this.ki = ki;
            this.ki64 = ki64;
            this.k164 = k164;
            this.k264 = k264;
            this.k364 = k364;
            this.mask = mask;
            ki_k3 = ki - k3;
            ki_k2 = ki - k2;
            ki_k1 = ki - k1;
        }

        public void rem_gf2n(long[] P, int p_cp, long[] Pol)
        {
            long Q8 = Pol[16] >>> ki;
            long Q0 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            long Q1 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
            /* 64-(k364+ki) == (k3-ki) */
            Q0 ^= (Q8 >>> ki_k3) ^ (Q8 >>> ki_k2) ^ (Q8 >>> ki_k1);
            P[p_cp] = Pol[0] ^ Q0 ^ (Q0 << k1) ^ (Q0 << k2) ^ (Q0 << k3);
            Q0 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            P[p_cp + 2] = Pol[2] ^ Q0 ^ (Q1 >>> k164) ^ (Q0 << k1) ^ (Q1 >>> k264) ^ (Q0 << k2) ^ (Q1 >>> k364) ^ (Q0 << k3);
            Q1 = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
            P[p_cp + 3] = Pol[3] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
            Q0 = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
            P[p_cp + 4] = Pol[4] ^ Q0 ^ (Q1 >>> k164) ^ (Q0 << k1) ^ (Q1 >>> k264) ^ (Q0 << k2) ^ (Q1 >>> k364) ^ (Q0 << k3);
            Q1 = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
            P[p_cp + 5] = Pol[5] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
            Q0 = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
            P[p_cp + 6] = Pol[6] ^ Q0 ^ (Q1 >>> k164) ^ (Q0 << k1) ^ (Q1 >>> k264) ^ (Q0 << k2) ^ (Q1 >>> k364) ^ (Q0 << k3);
            Q1 = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
            P[p_cp + 7] = Pol[7] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 8] = (Pol[8] ^ Q8 ^ (Q1 >>> k164) ^ (Q8 << k1) ^ (Q1 >>> k264) ^ (Q8 << k2) ^ (Q1 >>> k364) ^ (Q8 << k3)) & mask;
        }

        public void rem_gf2n_xor(long[] P, int p_cp, long[] Pol)
        {//KI: 25
            long Q8 = Pol[16] >>> ki;
            long Q0 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            long Q1 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            P[p_cp + 1] ^= Pol[1] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
            /* 64-(k364+ki) == (k3-ki) */
            Q0 ^= (Q8 >>> ki_k3) ^ (Q8 >>> ki_k2) ^ (Q8 >>> ki_k1);
            P[p_cp] ^= Pol[0] ^ Q0 ^ (Q0 << k1) ^ (Q0 << k2) ^ (Q0 << k3);
            Q0 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            P[p_cp + 2] ^= Pol[2] ^ Q0 ^ (Q1 >>> k164) ^ (Q0 << k1) ^ (Q1 >>> k264) ^ (Q0 << k2) ^ (Q1 >>> k364) ^ (Q0 << k3);
            Q1 = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
            P[p_cp + 3] ^= Pol[3] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
            Q0 = (Pol[12] >>> ki) ^ (Pol[13] << ki64);
            P[p_cp + 4] ^= Pol[4] ^ Q0 ^ (Q1 >>> k164) ^ (Q0 << k1) ^ (Q1 >>> k264) ^ (Q0 << k2) ^ (Q1 >>> k364) ^ (Q0 << k3);
            Q1 = (Pol[13] >>> ki) ^ (Pol[14] << ki64);
            P[p_cp + 5] ^= Pol[5] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
            Q0 = (Pol[14] >>> ki) ^ (Pol[15] << ki64);
            P[p_cp + 6] ^= Pol[6] ^ Q0 ^ (Q1 >>> k164) ^ (Q0 << k1) ^ (Q1 >>> k264) ^ (Q0 << k2) ^ (Q1 >>> k364) ^ (Q0 << k3);
            Q1 = (Pol[15] >>> ki) ^ (Pol[16] << ki64);
            P[p_cp + 7] ^= Pol[7] ^ Q1 ^ (Q0 >>> k164) ^ (Q1 << k1) ^ (Q0 >>> k264) ^ (Q1 << k2) ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 8] ^= (Pol[8] ^ Q8 ^ (Q1 >>> k164) ^ (Q8 << k1) ^ (Q1 >>> k264) ^ (Q8 << k2) ^ (Q1 >>> k364) ^ (Q8 << k3)) & mask;
        }
    }

    public static class REM384_SPECIALIZED_TRINOMIAL_GF2X
        extends Rem_GF2n
    {
        //gemss256
        private final int k3;
        private final int k364;
        private final int k364ki;
        private final int k3_ki;

        public REM384_SPECIALIZED_TRINOMIAL_GF2X(int k3, int ki, int ki64, int k364, long mask)
        {
            this.k3 = k3;
            this.ki = ki;
            this.ki64 = ki64;
            this.k364 = k364;
            this.mask = mask;
            k364ki = k364 + ki;
            k3_ki = k3 - ki;
        }

        public void rem_gf2n(long[] P, int p_cp, long[] Pol)
        {
            long Q2 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            long Q3 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            long Q4 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            long Q5 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            long Q0 = (Pol[5] >>> ki) ^ (Pol[6] << ki64) ^ (Q3 >>> (k364ki)) ^ (Q4 << (k3_ki));
            long Q1 = (Pol[6] >>> ki) ^ (Pol[7] << ki64) ^ (Q4 >>> (k364ki)) ^ (Q5 << (k3_ki));
            P[p_cp] = Pol[0] ^ Q0;
            P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 << k3);
            P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q1 >>> k364) ^ (Q2 << k3);
            P[p_cp + 4] = Pol[4] ^ Q4 ^ (Q2 >>> k364) ^ (Q3 << k3);
            P[p_cp + 5] = (Pol[5] ^ Q5 ^ (Q3 >>> k364)) & mask;
        }

        public void rem_gf2n_xor(long[] P, int p_cp, long[] Pol)
        {
            long Q2 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            long Q3 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            long Q4 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            long Q5 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            long Q0 = (Pol[5] >>> ki) ^ (Pol[6] << ki64) ^ (Q3 >>> (k364ki)) ^ (Q4 << (k3_ki));
            long Q1 = (Pol[6] >>> ki) ^ (Pol[7] << ki64) ^ (Q4 >>> (k364ki)) ^ (Q5 << (k3_ki));
            P[p_cp] ^= Pol[0] ^ Q0;
            P[p_cp + 1] ^= Pol[1] ^ Q1 ^ (Q0 << k3);
            P[p_cp + 2] ^= Pol[2] ^ Q2 ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 3] ^= Pol[3] ^ Q3 ^ (Q1 >>> k364) ^ (Q2 << k3);
            P[p_cp + 4] ^= Pol[4] ^ Q4 ^ (Q2 >>> k364) ^ (Q3 << k3);
            P[p_cp + 5] ^= (Pol[5] ^ Q5 ^ (Q3 >>> k364)) & mask;
        }
    }

    public static class REM384_SPECIALIZED358_TRINOMIAL_GF2X
        extends Rem_GF2n
    {
        //bluegemss256, redgemss256
        private final int k3;
        private final int k364;
        private final int k364ki;
        private final int k3_ki;

        public REM384_SPECIALIZED358_TRINOMIAL_GF2X(int k3, int ki, int ki64, int k364, long mask)
        {
            this.k3 = k3;
            this.ki = ki;
            this.ki64 = ki64;
            this.k364 = k364;
            this.mask = mask;
            k364ki = k364 + ki;
            k3_ki = k3 - ki;
        }

        public void rem_gf2n(long[] P, int p_cp, long[] Pol)
        {
            long Q1 = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
            long Q2 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
            long Q3 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
            Q2 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            P[p_cp + 4] = Pol[4] ^ Q2 ^ (Q3 >>> k364) ^ (Q2 << k3);
            Q3 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            long Q0 = (Pol[5] >>> ki) ^ (Pol[6] << ki64) ^ (Q2 >>> k364ki) ^ (Q3 << k3_ki);
            P[p_cp + 5] = (Pol[5] ^ Q3 ^ (Q2 >>> k364)) & mask;
            /* 64-(k364+ki) == (k3-ki) */
            P[p_cp] = Pol[0] ^ Q0 ^ (Q0 << k3);
            P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k364) ^ (Q1 << k3);
        }

        public void rem_gf2n_xor(long[] P, int p_cp, long[] Pol)
        {
            long Q1 = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
            long Q2 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            P[p_cp + 2] ^= Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
            long Q3 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            P[p_cp + 3] ^= Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
            Q2 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            P[p_cp + 4] ^= Pol[4] ^ Q2 ^ (Q3 >>> k364) ^ (Q2 << k3);
            Q3 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            P[p_cp + 5] ^= (Pol[5] ^ Q3 ^ (Q2 >>> k364)) & mask;
            Q2 = (Pol[5] >>> ki) ^ (Pol[6] << ki64) ^ (Q2 >>> k364ki) ^ (Q3 << k3_ki);
            /* 64-(k364+ki) == (k3-ki) */
            P[p_cp] ^= Pol[0] ^ Q2 ^ (Q2 << k3);
            P[p_cp + 1] ^= Pol[1] ^ Q1 ^ (Q2 >>> k364) ^ (Q1 << k3);
        }
    }

    public static class REM384_TRINOMIAL_GF2X
        extends Rem_GF2n
    {
        //whitegemss256, cyangemss256, magentagemss256
        private final int k3;
        private final int k364;
        private final int ki_k3;

        public REM384_TRINOMIAL_GF2X(int k3, int ki, int ki64, int k364, long mask)
        {
            this.k3 = k3;
            this.ki = ki;
            this.ki64 = ki64;
            this.k364 = k364;
            this.mask = mask;
            ki_k3 = ki - k3;
        }

        public void rem_gf2n(long[] P, int p_cp, long[] Pol)
        {
            long Q0 = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
            long Q1 = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
            long Q2 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            long Q3 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            long Q4 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            long Q5 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            long R = Q0 ^ (Q5 >>> ki_k3);
            P[p_cp] = Pol[0] ^ R ^ (R << k3);
            P[p_cp + 1] = Pol[1] ^ Q1 ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 2] = Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
            P[p_cp + 3] = Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
            P[p_cp + 4] = Pol[4] ^ Q4 ^ (Q3 >>> k364) ^ (Q4 << k3);
            P[p_cp + 5] = (Pol[5] ^ Q5 ^ (Q4 >>> k364) ^ (Q5 << k3)) & mask;
        }

        public void rem_gf2n_xor(long[] P, int p_cp, long[] Pol)
        {
            long Q0 = (Pol[5] >>> ki) ^ (Pol[6] << ki64);
            long Q1 = (Pol[6] >>> ki) ^ (Pol[7] << ki64);
            long Q2 = (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            long Q3 = (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            long Q4 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            long Q5 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            long R = Q0 ^ (Q5 >>> ki_k3);
            P[p_cp] ^= Pol[0] ^ R ^ (R << k3);
            P[p_cp + 1] ^= Pol[1] ^ Q1 ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 2] ^= Pol[2] ^ Q2 ^ (Q1 >>> k364) ^ (Q2 << k3);
            P[p_cp + 3] ^= Pol[3] ^ Q3 ^ (Q2 >>> k364) ^ (Q3 << k3);
            P[p_cp + 4] ^= Pol[4] ^ Q4 ^ (Q3 >>> k364) ^ (Q4 << k3);
            P[p_cp + 5] ^= (Pol[5] ^ Q5 ^ (Q4 >>> k364) ^ (Q5 << k3)) & mask;
        }
    }

    public static class REM402_SPECIALIZED_TRINOMIAL_GF2X
        extends Rem_GF2n
    {
        //fgmess192
        private final int k3;
        private final int k364;

        public REM402_SPECIALIZED_TRINOMIAL_GF2X(int k3, int ki, int ki64, int k364, long mask)
        {
            this.k3 = k3;
            this.ki = ki;
            this.ki64 = ki64;
            this.k364 = k364;
            this.mask = mask;
        }

        public void rem_gf2n(long[] P, int p_cp, long[] Pol)
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

        public void rem_gf2n_xor(long[] P, int p_cp, long[] Pol)
        {
            long Q3 = (Pol[9] >>> ki) ^ (Pol[10] << ki64);
            long Q4 = (Pol[10] >>> ki) ^ (Pol[11] << ki64);
            long Q5 = (Pol[11] >>> ki) ^ (Pol[12] << ki64);
            long Q6 = (Pol[12] >>> ki);
            long Q0 = (Q3 >>> 39) ^ (Q4 << 25) ^ (Pol[6] >>> ki) ^ (Pol[7] << ki64);
            long Q1 = (Q4 >>> 39) ^ (Q5 << 25) ^ (Pol[7] >>> ki) ^ (Pol[8] << ki64);
            long Q2 = (Q5 >>> 39) ^ (Q6 << 25) ^ (Pol[8] >>> ki) ^ (Pol[9] << ki64);
            P[p_cp] ^= Pol[0] ^ Q0;
            P[p_cp + 1] ^= Pol[1] ^ Q1;
            P[p_cp + 2] ^= Pol[2] ^ Q2 ^ (Q0 << k3);
            P[p_cp + 3] ^= Pol[3] ^ Q3 ^ (Q0 >>> k364) ^ (Q1 << k3);
            P[p_cp + 4] ^= Pol[4] ^ Q4 ^ (Q1 >>> k364) ^ (Q2 << k3);
            P[p_cp + 5] ^= Pol[5] ^ Q5 ^ (Q2 >>> k364) ^ (Q3 << k3);
            P[p_cp + 6] ^= (Pol[6] ^ Q6 ^ (Q3 >>> k364)) & mask;
        }
    }
}
