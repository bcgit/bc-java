package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Level-1 wrapper around {@link FpMontHelper64}'s 64-bit limb CIOS kernel,
 * specialised to the lvl1 prime {@code p = 5 * 2^248 - 1}. 4 limbs of 64 bits
 * = 256 bits ≥ 251.
 *
 * <p>Inputs to {@link #mulMont} are in Montgomery form ({@code a*R mod p} with
 * {@code R = 2^256}); the output is in Montgomery form, fully reduced.</p>
 */
final class FpLvl1Mont64
{
    static final int N = 4;

    static final long[] P_LIMBS;
    static final long[] R_SQR_MOD_P_LIMBS;
    static final long[] ONE_MONT_LIMBS;

    private static final long[] CANONICAL_ONE_LIMBS;

    /**
     * {@code 2·p²} as a {@code 2N+2}-limb little-endian constant. Added to the
     * Karatsuba sub-products before the single Montgomery reduction in
     * {@link #fp2Mul} to keep the (possibly negative) combination
     * {@code P_ac − P_bd} / {@code P_sum − P_ac − P_bd} non-negative and below
     * {@code p·R}. {@code 2p²} is a multiple of p (so it vanishes mod p under
     * REDC) and {@code 3p² < p·R} (since {@code 3p < R}), keeping the reduced
     * input in range.
     */
    private static final long[] BIAS_2P2;

    static
    {
        P_LIMBS = new long[N];
        FpMontHelper64.toLimbs(N, FpLvl1.P, P_LIMBS);
        BigInteger R = BigInteger.ONE.shiftLeft(64 * N);
        R_SQR_MOD_P_LIMBS = new long[N];
        FpMontHelper64.toLimbs(N, R.multiply(R).mod(FpLvl1.P), R_SQR_MOD_P_LIMBS);
        ONE_MONT_LIMBS = new long[N];
        FpMontHelper64.toLimbs(N, R.mod(FpLvl1.P), ONE_MONT_LIMBS);
        CANONICAL_ONE_LIMBS = new long[N];
        CANONICAL_ONE_LIMBS[0] = 1L;
        BIAS_2P2 = FpMontHelper64.bias2P2(N, FpLvl1.P);
    }

    private FpLvl1Mont64()
    {
    }

    // BigInteger ↔ limbs

    static long[] toLimbs(BigInteger v)
    {
        long[] r = new long[N];
        FpMontHelper64.toLimbs(N, v, r);
        return r;
    }

    static void toLimbs(BigInteger v, long[] out)
    {
        FpMontHelper64.toLimbs(N, v, out);
    }

    static BigInteger fromLimbs(long[] limbs)
    {
        return FpMontHelper64.fromLimbs(N, limbs);
    }

    // Montgomery domain transfer

    static void toMont(long[] out, long[] a)
    {
        mulMont(out, a, R_SQR_MOD_P_LIMBS);
    }

    static void fromMont(long[] out, long[] aM)
    {
        mulMont(out, aM, CANONICAL_ONE_LIMBS);
    }

    // Modular add / sub

    static void addModP(long[] out, long[] a, long[] b)
    {
        FpMontHelper64.addModP(N, P_LIMBS, out, a, b);
    }

    static void subModP(long[] out, long[] a, long[] b)
    {
        FpMontHelper64.subModP(N, P_LIMBS, out, a, b);
    }

    // CIOS Montgomery multiplication / squaring

    static void mulMont(long[] c, long[] a, long[] b)
    {
        FpMontHelper64.mulMont(N, P_LIMBS, c, a, b);
    }

    static void sqrMont(long[] c, long[] a)
    {
        mulMont(c, a, a);
    }

    /**
     * Lazy-reduction GF(p²) multiply on Mont-form limb arrays:
     * {@code (aRe + aIm·i)(bRe + bIm·i) = (ac − bd) + ((a+b)(c+d) − ac − bd)i}.
     * Computes the three Karatsuba sub-products as full {@code 2N}-limb integers
     * (no per-product Montgomery reduction), combines them in wide integer space
     * with the {@code 2p²} bias to stay non-negative and below {@code p·R}, then
     * does just <b>two</b> Montgomery reductions (one per output component)
     * instead of the three a Karatsuba of separate {@code mulMont}s would need.
     * ~17% fewer limb-multiplies than the reduce-per-product path.
     *
     * <p>All six inputs are N-limb Mont-form ({@code < p}); both outputs are
     * written Mont-form. Output arrays may alias inputs — all products are
     * formed before either output is written.</p>
     */
    static void fp2Mul(long[] outRe, long[] outIm,
                       long[] aRe, long[] aIm, long[] bRe, long[] bIm)
    {
        FpMontHelper64.fp2Mul(N, P_LIMBS, BIAS_2P2, outRe, outIm, aRe, aIm, bRe, bIm);
    }

    /** Materialise {@code x.v} from {@code x.mont64} for a lvl1 cell. */
    static void materializeV(Fp x)
    {
        fromMont(x.canonScratch64, x.mont64);
        x.v = fromLimbs(x.canonScratch64);
    }
}
