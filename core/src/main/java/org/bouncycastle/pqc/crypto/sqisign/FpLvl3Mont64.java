package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Level-3 wrapper around {@link FpMontHelper64}'s 64-bit limb CIOS kernel.
 * Lvl3 prime {@code p = 65 * 2^376 - 1} (383-bit) → 6 limbs of 64 bits = 384 bits.
 */
final class FpLvl3Mont64
{
    static final int N = 6;

    static final long[] P_LIMBS;
    static final long[] R_SQR_MOD_P_LIMBS;
    static final long[] ONE_MONT_LIMBS;
    private static final long[] CANONICAL_ONE_LIMBS;
    /** {@code 2·p²} bias for the lazy-reduction Fp2 multiply. See FpLvl1Mont64. */
    private static final long[] BIAS_2P2;

    static
    {
        P_LIMBS = new long[N];
        FpMontHelper64.toLimbs(N, FpLvl3.P, P_LIMBS);
        BigInteger R = BigInteger.ONE.shiftLeft(64 * N);
        R_SQR_MOD_P_LIMBS = new long[N];
        FpMontHelper64.toLimbs(N, R.multiply(R).mod(FpLvl3.P), R_SQR_MOD_P_LIMBS);
        ONE_MONT_LIMBS = new long[N];
        FpMontHelper64.toLimbs(N, R.mod(FpLvl3.P), ONE_MONT_LIMBS);
        CANONICAL_ONE_LIMBS = new long[N];
        CANONICAL_ONE_LIMBS[0] = 1L;
        BIAS_2P2 = FpMontHelper64.bias2P2(N, FpLvl3.P);
    }

    private FpLvl3Mont64()
    {
    }

    static void toLimbs(BigInteger v, long[] out)
    {
        FpMontHelper64.toLimbs(N, v, out);
    }

    static BigInteger fromLimbs(long[] limbs)
    {
        return FpMontHelper64.fromLimbs(N, limbs);
    }

    static void toMont(long[] out, long[] a)
    {
        mulMont(out, a, R_SQR_MOD_P_LIMBS);
    }

    static void fromMont(long[] out, long[] aM)
    {
        mulMont(out, aM, CANONICAL_ONE_LIMBS);
    }

    static void addModP(long[] out, long[] a, long[] b)
    {
        FpMontHelper64.addModP(N, P_LIMBS, out, a, b);
    }

    static void subModP(long[] out, long[] a, long[] b)
    {
        FpMontHelper64.subModP(N, P_LIMBS, out, a, b);
    }

    static void mulMont(long[] c, long[] a, long[] b)
    {
        FpMontHelper64.mulMont(N, P_LIMBS, c, a, b);
    }

    static void sqrMont(long[] c, long[] a)
    {
        mulMont(c, a, a);
    }

    /** Lazy-reduction GF(p²) multiply — see {@code FpLvl1Mont64.fp2Mul}. */
    static void fp2Mul(long[] outRe, long[] outIm,
                       long[] aRe, long[] aIm, long[] bRe, long[] bIm)
    {
        FpMontHelper64.fp2Mul(N, P_LIMBS, BIAS_2P2, outRe, outIm, aRe, aIm, bRe, bIm);
    }

    static void materializeV(Fp x)
    {
        fromMont(x.canonScratch64, x.mont64);
        x.v = fromLimbs(x.canonScratch64);
    }
}
