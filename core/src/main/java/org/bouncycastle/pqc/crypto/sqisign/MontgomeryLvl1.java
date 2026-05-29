package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Conversion between the C reference's redundant 5-limb-of-51-bit
 * Montgomery representation (used in {@code src/gf/ref/lvl1/fp_p5248_64.c} and
 * in precomp constant tables) and the canonical {@link BigInteger} form
 * used by the Java port.
 *
 * <p>The C representation stores a value as five 64-bit limbs
 * {@code [l0, l1, l2, l3, l4]} where each limb holds 51 useful bits. The
 * "redundant" radix-51 integer is {@code Σ_{i=0..4} l_i · 2^(51·i)}. The
 * Montgomery form is this integer reduced mod p and then multiplied by
 * R = 2^255 (the radix of the 5-limb-of-51-bit representation).</p>
 *
 * <p>The published precomp tables in the C reference are stored as
 * little-endian arrays of 5 unsigned 64-bit values. This class converts those
 * directly to {@link BigInteger} mod p, which is the canonical form used
 * everywhere else in the Java port.</p>
 */
final class MontgomeryLvl1
{
    /**
     * The Montgomery radix R = 2^255.
     */
    public static final BigInteger R = BigInteger.ONE.shiftLeft(255);

    /**
     * R⁻¹ mod p, precomputed once.
     */
    public static final BigInteger R_INV_MOD_P = R.modInverse(FpLvl1.P);

    private MontgomeryLvl1()
    {
    }

    /**
     * Convert a C-format 5-limb Montgomery value to canonical {@link BigInteger}
     * in {@code [0, p)}. Each {@code limbs[i]} is interpreted as an unsigned
     * 64-bit value whose low 51 bits are the i-th radix-51 digit.
     *
     * @param limbs array of length 5 holding the C reference's stored
     *              Montgomery limbs.
     * @return the canonical value {@code limbs · R⁻¹ mod p}.
     */
    public static BigInteger fromMontgomery5x51(long[] limbs)
    {
        if (limbs.length != 5)
        {
            throw new IllegalArgumentException("expected 5 limbs");
        }
        // Reassemble the redundant 51-bit-per-limb integer.
        BigInteger m = BigInteger.ZERO;
        for (int i = 4; i >= 0; i--)
        {
            BigInteger limb = BigInteger.valueOf(limbs[i]);
            // mask out anything above bit 51 (the C code keeps that disabled
            // but stored constants are within the bound).
            if (limbs[i] < 0)
            {
                // treat as unsigned 64-bit
                limb = limb.add(BigInteger.ONE.shiftLeft(64));
            }
            m = m.shiftLeft(51).add(limb);
        }
        m = m.mod(FpLvl1.P);
        return m.multiply(R_INV_MOD_P).mod(FpLvl1.P);
    }

    /**
     * Convert a canonical {@link BigInteger} (mod p) to the C-format 5-limb
     * Montgomery representation. Inverse of {@link #fromMontgomery5x51}.
     *
     * @param v value in {@code [0, p)}.
     * @return array of length 5 with the C reference's limb layout.
     */
    /**
     * Convenience: decode a pair of Montgomery limb arrays representing a
     * GF(p²) element (re, im) into canonical {@code (re, im)} BigIntegers.
     *
     * @param reLimbs limbs of the real part.
     * @param imLimbs limbs of the imaginary part.
     * @return length-2 array {@code [re, im]}.
     */
    public static BigInteger[] fp2FromMontgomery5x51(long[] reLimbs, long[] imLimbs)
    {
        return new BigInteger[]{
            fromMontgomery5x51(reLimbs),
            fromMontgomery5x51(imLimbs)
        };
    }
}
