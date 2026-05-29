package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Level-5 wrapper around {@link FpMontHelper}'s limb-array CIOS Montgomery
 * arithmetic, specialised to the lvl5 prime {@code p = 27 * 2^500 - 1}
 * (505-bit). Provides {@code mulMont}, {@code sqrMont}, {@code toMont},
 * {@code fromMont}, plus modular {@code addModP} / {@code subModP} over
 * little-endian 32-bit limb arrays of length {@link #N} = 16.
 *
 * <p>Inputs to {@link #mulMont} are in Montgomery form ({@code a*R mod p}
 * with {@code R = 2^{32N} = 2^512}); the output is in Montgomery form,
 * fully reduced to {@code [0, p)}.</p>
 *
 * <p>Verified against a BigInteger oracle.</p>
 */
final class FpLvl5Mont
{
    /**
     * Number of 32-bit little-endian limbs. {@code 16 × 32 = 512 ≥ 505} bits.
     */
    static final int N = 16;

    static final int[] P_LIMBS;
    static final int[] R_SQR_MOD_P_LIMBS;
    static final int[] ONE_MONT_LIMBS;

    private static final int[] CANONICAL_ONE_LIMBS;

    static
    {
        P_LIMBS = new int[N];
        FpMontHelper.toLimbs(N, FpLvl5.P, P_LIMBS);
        BigInteger R = BigInteger.ONE.shiftLeft(32 * N);
        R_SQR_MOD_P_LIMBS = new int[N];
        FpMontHelper.toLimbs(N, R.multiply(R).mod(FpLvl5.P), R_SQR_MOD_P_LIMBS);
        ONE_MONT_LIMBS = new int[N];
        FpMontHelper.toLimbs(N, R.mod(FpLvl5.P), ONE_MONT_LIMBS);
        CANONICAL_ONE_LIMBS = new int[N];
        CANONICAL_ONE_LIMBS[0] = 1;
    }

    private FpLvl5Mont()
    {
    }

    static int[] toLimbs(BigInteger v)
    {
        int[] r = new int[N];
        FpMontHelper.toLimbs(N, v, r);
        return r;
    }

    static void toLimbs(BigInteger v, int[] out)
    {
        FpMontHelper.toLimbs(N, v, out);
    }

    static BigInteger fromLimbs(int[] limbs)
    {
        return FpMontHelper.fromLimbs(N, limbs);
    }

    static void toMont(int[] out, int[] a)
    {
        mulMont(out, a, R_SQR_MOD_P_LIMBS);
    }

    static void fromMont(int[] out, int[] aM)
    {
        mulMont(out, aM, CANONICAL_ONE_LIMBS);
    }

    static void addModP(int[] out, int[] a, int[] b)
    {
        FpMontHelper.addModP(N, P_LIMBS, out, a, b);
    }

    static void subModP(int[] out, int[] a, int[] b)
    {
        FpMontHelper.subModP(N, P_LIMBS, out, a, b);
    }

    static void mulMont(int[] c, int[] a, int[] b)
    {
        FpMontHelper.mulMont(N, P_LIMBS, c, a, b);
    }

    static void sqrMont(int[] c, int[] a)
    {
        mulMont(c, a, a);
    }

    /**
     * See {@link FpLvl1Mont#materializeV(Fp)}.
     */
    static void materializeV(Fp x)
    {
        fromMont(x.canonScratch, x.mont);
        x.v = fromLimbs(x.canonScratch);
    }
}
