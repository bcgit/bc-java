package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;

/**
 * Scalar constants for SQIsign level 5. Java mirror of the level-5 entries
 * in {@code src/precomp/ref/lvl5/}.
 *
 * <p><b>What this file provides:</b> all the level-specific scalar
 * constants — prime p, torsion exponent, security parameters, FINDUV
 * search-box sizes, SEC/COM_DEGREE, the {@code QUAT_*} hyperparameters,
 * and signature/key byte sizes.</p>
 *
 * <p><b>What it does NOT yet provide</b> (needed for lvl5 keygen/sign/verify
 * to actually run):</p>
 * <ul>
 *   <li>{@code FpLvl5} / {@code Fp2Lvl5} arithmetic modules — analogues of
 *       {@code FpLvl1} / {@code Fp2Lvl1} parameterized over the lvl5 prime
 *       (a 505-bit value).</li>
 *   <li>Lvl5 versions of the precomp data tables:
 *       {@code EXTREMAL_ORDERS[7]}, {@code CONNECTING_IDEALS[7]},
 *       {@code CURVES_WITH_ENDOMORPHISMS[7]}. Each has ~7K LOC of constants
 *       in the C reference (under
 *       {@code src/precomp/ref/lvl5/}); extract via
 *       {@code core/src/tools/python/extract_sqisign_precomp.py}.</li>
 *   <li>Lvl5 versions of the EC / HD / id2iso / signature driver classes
 *       (analogues of {@code EcBasisLvl1}, {@code ThetaChainLvl1},
 *       {@code Dim2Id2IsoLvl1}, {@code SQIsignSignLvl1},
 *       {@code SQIsignVerifyLvl1}). See the corresponding lvl3 file's
 *       header for the structural notes.</li>
 * </ul>
 */
final class PrecompLvl5
{
    /**
     * Lvl5 prime: {@code p = 27·2^500 - 1}. A 505-bit prime with
     * {@code p ≡ 3 (mod 4)}. Confirmed against
     * {@code src/precomp/ref/lvl5/quaternion_data.c} GMP-64 branch.
     */
    public static final BigInteger P =
        BigInteger.valueOf(27).shiftLeft(500).subtract(BigInteger.ONE);

    /**
     * Odd cofactor of p+1. For lvl5, {@code p + 1 = 27·2^500}, so the
     * cofactor is 27 = 3^3.
     */
    public static final BigInteger P_COFACTOR_FOR_2F = BigInteger.valueOf(27);

    /**
     * 2-power torsion exponent: {@code E[2^500]} on the lvl5 starting curve.
     * From {@code src/precomp/ref/lvl5/include/ec_params.h}.
     */
    public static final int TORSION_EVEN_POWER = 500;

    /**
     * {@code TORSION_PLUS_2POWER}: 2^TORSION_EVEN_POWER.
     */
    public static final BigInteger TORSION_PLUS_2POWER =
        BigInteger.ONE.shiftLeft(TORSION_EVEN_POWER);

    /**
     * NIST level-5 security parameter (256 bits).
     */
    public static final int SECURITY_BITS = 256;

    /**
     * Bit-length of the response scalars in a lvl5 signature.
     */
    public static final int SQIsign_RESPONSE_LENGTH = 253;

    /**
     * Number of SHAKE256 iterations in {@code hash_to_challenge}.
     */
    public static final int HASH_ITERATIONS = 512;

    /**
     * Secret-key isogeny degree target: {@code SEC_DEGREE = 2^1024 + 643}.
     * From {@code src/precomp/ref/lvl5/torsion_constants.c}.
     */
    public static final BigInteger SEC_DEGREE =
        BigInteger.ONE.shiftLeft(1024).add(BigInteger.valueOf(643));

    /**
     * Commitment isogeny degree target: identical to {@link #SEC_DEGREE} for lvl5.
     */
    public static final BigInteger COM_DEGREE = SEC_DEGREE;

    /**
     * {@code QUAT_primality_num_iter}: 32 (same across levels).
     */
    public static final int QUAT_PRIMALITY_NUM_ITER = 32;

    /**
     * {@code QUAT_repres_bound_input}: 21 for lvl5 (same as lvl3).
     */
    public static final int QUAT_REPRES_BOUND_INPUT = 21;

    /**
     * {@code QUAT_equiv_bound_coeff}: 64 (same as lvl1).
     */
    public static final int QUAT_EQUIV_BOUND_COEFF = 64;

    /**
     * {@code FINDUV_box_size}: 3 for lvl5 (same as lvl3).
     */
    public static final int FINDUV_BOX_SIZE = 3;

    /**
     * {@code FINDUV_cube_size}: 2400 for lvl5 (same as lvl3).
     */
    public static final int FINDUV_CUBE_SIZE = 2400;

    /**
     * Number of alternate extremal orders (6, same across levels).
     */
    public static final int NUM_ALTERNATE_EXTREMAL_ORDERS = 6;

    /**
     * {@code HD_extra_torsion}: 2 (level-independent).
     */
    public static final int HD_EXTRA_TORSION = 2;

    /**
     * Ibz wrapper of {@link #TORSION_PLUS_2POWER} — used by find_uv.
     */
    public static final Ibz IBZ_TORSION_PLUS_2POWER = new Ibz(TORSION_PLUS_2POWER);

    /**
     * Ibz wrapper of {@link #SEC_DEGREE} — used by keygen step 1.
     */
    public static final Ibz IBZ_SEC_DEGREE = new Ibz(SEC_DEGREE);

    private PrecompLvl5()
    {
    }
}
