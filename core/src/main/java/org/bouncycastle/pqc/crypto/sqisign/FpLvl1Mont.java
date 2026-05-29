package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Level-1 wrapper around {@link FpMontHelper}'s limb-array CIOS Montgomery
 * arithmetic, specialised to the lvl1 prime {@code p = 5 * 2^248 - 1}.
 * Provides {@code mulMont}, {@code sqrMont}, {@code toMont}, {@code fromMont},
 * plus modular {@code addModP} / {@code subModP} over little-endian 32-bit
 * limb arrays of length {@link #N} = 8.
 *
 * <p>Inputs to {@link #mulMont} are in Montgomery form (each operand
 * represents {@code a*R mod p} with {@code R = 2^{32N} = 2^256}); the output
 * is also in Montgomery form, fully reduced to {@code [0, p)}. Use
 * {@link #toMont} / {@link #fromMont} at the conversion boundaries.</p>
 *
 * <p>Verified against a BigInteger oracle; a standalone benchmark measured
 * ~3.1× speedup on the raw multiply (with operands pre-Montgomery and no
 * per-call conversion).</p>
 */
final class FpLvl1Mont
{
    /** Number of 32-bit little-endian limbs. {@code 8 × 32 = 256 ≥ 251} bits. */
    static final int N = 8;

    /** Prime modulus as an {@code int[N]} array of unsigned 32-bit limbs. */
    static final int[] P_LIMBS;

    /** {@code R^2 mod p} (R = 2^{32N} = 2^256), used by {@link #toMont}. */
    static final int[] R_SQR_MOD_P_LIMBS;

    /** {@code 1} in Montgomery form ({@code R mod p}). */
    static final int[] ONE_MONT_LIMBS;

    /** Canonical 1 as limbs (lowest limb 1, rest 0). Used by {@link #fromMont}. */
    private static final int[] CANONICAL_ONE_LIMBS;

    static
    {
        P_LIMBS = new int[N];
        FpMontHelper.toLimbs(N, FpLvl1.P, P_LIMBS);
        BigInteger R = BigInteger.ONE.shiftLeft(32 * N);
        R_SQR_MOD_P_LIMBS = new int[N];
        FpMontHelper.toLimbs(N, R.multiply(R).mod(FpLvl1.P), R_SQR_MOD_P_LIMBS);
        ONE_MONT_LIMBS = new int[N];
        FpMontHelper.toLimbs(N, R.mod(FpLvl1.P), ONE_MONT_LIMBS);
        CANONICAL_ONE_LIMBS = new int[N];
        CANONICAL_ONE_LIMBS[0] = 1;
    }

    private FpLvl1Mont()
    {
    }

    // BigInteger ↔ limbs

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

    // Montgomery domain transfer

    static void toMont(int[] out, int[] a)
    {
        mulMont(out, a, R_SQR_MOD_P_LIMBS);
    }

    static void fromMont(int[] out, int[] aM)
    {
        mulMont(out, aM, CANONICAL_ONE_LIMBS);
    }

    // Modular add / sub

    static void addModP(int[] out, int[] a, int[] b)
    {
        FpMontHelper.addModP(N, P_LIMBS, out, a, b);
    }

    static void subModP(int[] out, int[] a, int[] b)
    {
        FpMontHelper.subModP(N, P_LIMBS, out, a, b);
    }

    // CIOS Montgomery multiplication / squaring

    static void mulMont(int[] c, int[] a, int[] b)
    {
        FpMontHelper.mulMont(N, P_LIMBS, c, a, b);
    }

    static void sqrMont(int[] c, int[] a)
    {
        mulMont(c, a, a);
    }

    /**
     * Materialise {@code x.v} from {@code x.mont} for a lvl1 cell whose
     * latest update came from a Mont-domain op. Uses {@code x.canonScratch}
     * as the fromMont destination. Caller is responsible for setting
     * {@code x.vInSync = true} (typically {@link Fp#ensureV} does this).
     */
    static void materializeV(Fp x)
    {
        fromMont(x.canonScratch, x.mont);
        x.v = fromLimbs(x.canonScratch);
    }
}
