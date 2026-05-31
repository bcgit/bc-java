package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Scalar constants for SQIsign level 3. Java mirror of the level-3 entries
 * in {@code src/precomp/ref/lvl3/}.
 *
 * <p><b>What this file provides:</b> all the level-specific scalar
 * constants — prime p, torsion exponent, security parameters, FINDUV
 * search-box sizes, SEC/COM_DEGREE, the {@code QUAT_*} hyperparameters,
 * and signature/key byte sizes.</p>
 *
 * <p><b>What it does NOT yet provide</b> (needed for lvl3 keygen/sign/verify
 * to actually run):</p>
 * <ul>
 *   <li>{@code FpLvl3} / {@code Fp2Lvl3} arithmetic modules — analogues of
 *       {@code FpLvl1} / {@code Fp2Lvl1} parameterized over the lvl3 prime
 *       (a 383-bit value).</li>
 *   <li>Lvl3 versions of the precomp data tables:
 *       {@code EXTREMAL_ORDERS[7]}, {@code CONNECTING_IDEALS[7]},
 *       {@code CURVES_WITH_ENDOMORPHISMS[7]}. Each has ~7K LOC of constants
 *       in the C reference (under
 *       {@code src/precomp/ref/lvl3/}); extract via
 *       {@code core/src/tools/python/extract_sqisign_precomp.py}.</li>
 *   <li>Lvl3 versions of the EC / HD / id2iso / signature driver classes
 *       (analogues of {@code EcBasisLvl1}, {@code ThetaChainLvl1},
 *       {@code Dim2Id2IsoLvl1}, {@code SQIsignSignLvl1},
 *       {@code SQIsignVerifyLvl1}). These are largely level-independent in
 *       structure but read {@code FpLvl1} / {@code Fp2Lvl1} by name today;
 *       a parameterised refactor or duplication-per-level is required.</li>
 * </ul>
 */
final class PrecompLvl3
{
    /**
     * Lvl3 prime: {@code p = 65·2^376 - 1}. A 383-bit prime with
     * {@code p ≡ 3 (mod 4)}. Confirmed against
     * {@code src/precomp/ref/lvl3/quaternion_data.c} GMP-64 branch.
     */
    public static final BigInteger P =
        BigInteger.valueOf(65).shiftLeft(376).subtract(BigInteger.ONE);

    /**
     * Odd cofactor of p+1. For lvl3, {@code p + 1 = 65·2^376}, so the
     * cofactor is 65 = 5·13.
     */
    public static final BigInteger P_COFACTOR_FOR_2F = BigInteger.valueOf(65);

    /**
     * 2-power torsion exponent: {@code E[2^376]} on the lvl3 starting curve.
     * From {@code src/precomp/ref/lvl3/include/ec_params.h}.
     */
    public static final int TORSION_EVEN_POWER = 376;

    /** {@code TORSION_PLUS_2POWER}: 2^TORSION_EVEN_POWER. */
    public static final BigInteger TORSION_PLUS_2POWER =
        BigInteger.ONE.shiftLeft(TORSION_EVEN_POWER);

    /** NIST level-3 security parameter (192 bits). */
    public static final int SECURITY_BITS = 192;

    /** Bit-length of the response scalars in a lvl3 signature. */
    public static final int SQIsign_RESPONSE_LENGTH = 192;

    /** Number of SHAKE256 iterations in {@code hash_to_challenge}. */
    public static final int HASH_ITERATIONS = 256;

    /**
     * Secret-key isogeny degree target: {@code SEC_DEGREE = 2^768 + 183}.
     * From {@code src/precomp/ref/lvl3/torsion_constants.c}.
     */
    public static final BigInteger SEC_DEGREE =
        BigInteger.ONE.shiftLeft(768).add(BigInteger.valueOf(183));

    /** Commitment isogeny degree target: identical to {@link #SEC_DEGREE} for lvl3. */
    public static final BigInteger COM_DEGREE = SEC_DEGREE;

    /** {@code QUAT_primality_num_iter}: 32 (same across levels). */
    public static final int QUAT_PRIMALITY_NUM_ITER = 32;

    /** {@code QUAT_repres_bound_input}: 21 for lvl3 (vs 20 for lvl1). */
    public static final int QUAT_REPRES_BOUND_INPUT = 21;

    /** {@code QUAT_equiv_bound_coeff}: 64 (same as lvl1). */
    public static final int QUAT_EQUIV_BOUND_COEFF = 64;

    /** {@code FINDUV_box_size}: 3 for lvl3 (vs 2 for lvl1). */
    public static final int FINDUV_BOX_SIZE = 3;

    /** {@code FINDUV_cube_size}: 2400 for lvl3 (vs 624 for lvl1). */
    public static final int FINDUV_CUBE_SIZE = 2400;

    /** Number of alternate extremal orders for lvl3 (7 alternates → 8 total). */
    public static final int NUM_ALTERNATE_EXTREMAL_ORDERS = 7;

    /** {@code HD_extra_torsion}: 2 (level-independent). */
    public static final int HD_EXTRA_TORSION = 2;

    /** Ibz wrapper of {@link #TORSION_PLUS_2POWER} — used by find_uv. */
    public static final Ibz IBZ_TORSION_PLUS_2POWER = new Ibz(TORSION_PLUS_2POWER);

    /** Ibz wrapper of {@link #SEC_DEGREE} — used by keygen step 1. */
    public static final Ibz IBZ_SEC_DEGREE = new Ibz(SEC_DEGREE);

    private PrecompLvl3()
    {
    }
}
