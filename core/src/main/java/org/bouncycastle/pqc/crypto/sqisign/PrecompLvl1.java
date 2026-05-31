package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Precomputed scalar constants for SQIsign level 1. Java mirror of the
 * level-1 entries in {@code src/precomp/ref/lvl1/}.
 *
 * <p>This class holds only the scalar / integer constants. The larger
 * tables — endomorphism action matrices, extremal-order data and the
 * basis-change matrices for the gluing isomorphism, which the C reference
 * stores in Montgomery 5×51-bit limb form — live in their own dedicated
 * classes (e.g. {@link EndomorphismActionLvl1}) in canonical
 * {@link BigInteger} form.</p>
 */
final class PrecompLvl1
{
    /**
     * The level-1 prime p = 5·2^248 − 1 = 0x4FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF.
     * Re-exported from {@link FpLvl1#P} for convenience.
     */
    public static final BigInteger P = FpLvl1.P;

    /**
     * Number of Miller-Rabin iterations for primality tests inside the
     * quaternion subsystem. From {@code QUAT_primality_num_iter} in
     * {@code precomp/ref/lvl1/include/quaternion_constants.h}.
     */
    public static final int QUAT_PRIMALITY_NUM_ITER = 32;

    /**
     * Bit-headroom added on top of the input target norm when looking for a
     * representation. From {@code QUAT_repres_bound_input}.
     */
    public static final int QUAT_REPRES_BOUND_INPUT = 20;

    /**
     * Half-range of integer coefficients used by
     * {@code primeNormReducedEquivalent}'s random-combination search.
     * From {@code QUAT_equiv_bound_coeff}.
     */
    public static final int QUAT_EQUIV_BOUND_COEFF = 64;

    /**
     * Exponent of the maximal even-torsion subgroup: E[2^TORSION_EVEN_POWER].
     * For lvl1, derived from p+1 = 5·2^248; the 2-adic valuation is 248.
     */
    public static final int TORSION_EVEN_POWER = 248;

    /** {@code TORSION_PLUS_2POWER}: 2^{@link #TORSION_EVEN_POWER}. */
    public static final BigInteger TORSION_PLUS_2POWER =
        BigInteger.ONE.shiftLeft(TORSION_EVEN_POWER);

    /**
     * Odd cofactor (p + 1) / 2^{@link #TORSION_EVEN_POWER}. For lvl1, p = 5·2^248 − 1
     * so (p + 1) / 2^248 = 5.
     */
    public static final BigInteger P_COFACTOR_FOR_2F = BigInteger.valueOf(5);

    /**
     * {@code SEC_DEGREE}: secret-key isogeny degree target.
     * From torsion_constants.c lvl1: {@code 2^512 + 75}.
     */
    public static final BigInteger SEC_DEGREE =
        BigInteger.ONE.shiftLeft(512).add(BigInteger.valueOf(75));

    /**
     * {@code COM_DEGREE}: commitment isogeny degree target.
     * For lvl1, identical to {@link #SEC_DEGREE}.
     */
    public static final BigInteger COM_DEGREE = SEC_DEGREE;

    /**
     * {@code QUATALG_PINFTY}: the quaternion algebra over Q ramified at p
     * (and at infinity), used throughout the SQIsign quaternion subsystem.
     */
    public static final QuatAlg QUATALG_PINFTY = new QuatAlg(P);

    /**
     * {@code FINDUV_box_size}: half-radius of the infinity-norm hypercube
     * searched by {@code enumerate_hypercube} in {@code find_uv}. lvl1: 2.
     * From {@code precomp/ref/lvl1/include/quaternion_constants.h}.
     */
    public static final int FINDUV_BOX_SIZE = 2;

    /**
     * {@code FINDUV_cube_size}: upper bound on the number of vectors
     * returned by {@code enumerate_hypercube}. Used for VLA sizing in C; in
     * Java we use it as the allocation size for the vec / norm buffers.
     * lvl1: 624.
     */
    public static final int FINDUV_CUBE_SIZE = 624;

    /**
     * {@code NUM_ALTERNATE_EXTREMAL_ORDERS}: number of alternate extremal
     * orders the clapotis search iterates over (in addition to the standard
     * O₀). lvl1: 6, so the full search ranges over orders 0..6.
     * From {@code precomp/ref/lvl1/include/quaternion_data.h}.
     */
    public static final int NUM_ALTERNATE_EXTREMAL_ORDERS = 6;

    /**
     * {@code HD_extra_torsion}: extra 2-power torsion reserved on the
     * codomain curve for the dimension-2 isogeny chain. Level-independent
     * (from {@code src/hd/ref/include/hd.h}) but exposed here for
     * convenience. Value: 2.
     */
    public static final int HD_EXTRA_TORSION = 2;

    /**
     * {@code SQIsign_response_length}: bit-length of the response scalars in
     * the signature. Lvl1: 126.
     */
    public static final int SQIsign_RESPONSE_LENGTH = 126;

    /**
     * {@code SECURITY_BITS}: NIST level-1 security parameter (128 bits).
     */
    public static final int SECURITY_BITS = 128;

    /**
     * {@code HASH_ITERATIONS}: number of SHAKE256 iterations in
     * {@code hash_to_challenge}. Lvl1: 64. (Lvl3: 256, lvl5: 512.)
     */
    public static final int HASH_ITERATIONS = 64;

    /** Pre-wrapped Ibz views of the key scalar constants. */
    public static final Ibz IBZ_SEC_DEGREE = new Ibz(SEC_DEGREE);
    public static final Ibz IBZ_TORSION_PLUS_2POWER = new Ibz(TORSION_PLUS_2POWER);

    private PrecompLvl1()
    {
    }
}
