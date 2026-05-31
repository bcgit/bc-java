package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;


/**
 * Level-1 E₀ basis constants. Java mirror of
 * {@code src/precomp/ref/lvl1/e0_basis.c}: the x-coordinates of the
 * pre-computed generators P, Q of E₀[2^TORSION_EVEN_POWER] used by
 * {@code ec_basis_E0_2f} (the curve-A=0 branch of
 * {@code ec_curve_to_basis_2f_*}).
 *
 * <p>The C reference stores these as 5-limb-of-51-bit Montgomery values; we
 * convert via {@link MontgomeryLvl1#fromMontgomery5x51} at class load. The
 * result is canonical {@link BigInteger} mod p, suitable for direct use in
 * the Java EC arithmetic.</p>
 */
final class E0BasisLvl1
{
    /** x-coordinate of the deterministic basis point P on E₀. */
    public static final Fp2 BASIS_E0_PX = mkFp2(
        new long[]{
            0x5bcab12000c08L,
            0x452654b56d052L,
            0x26f81b5190a0aL,
            0x36cfd66a361ebL,
            0x12726610d11bL
        },
        new long[]{
            0x6b96065c83efcL,
            0x29da1d4a82cd9L,
            0x190797ab98bdfL,
            0x6841aa6eeee05L,
            0x1377c5431166L
        });

    /** x-coordinate of the deterministic basis point Q on E₀. */
    public static final Fp2 BASIS_E0_QX = mkFp2(
        new long[]{
            0x21dd55b97832fL,
            0x210f2d30b26adL,
            0x680bcfcf6396L,
            0x27b318ec126a7L,
            0x4ffba5956012L
        },
        new long[]{
            0x74590149117e3L,
            0x4982edefcc606L,
            0x2ae3db0cc6884L,
            0x7d0384872f5ecL,
            0x4fbb0fcb5a52L
        });

    /**
     * x-coordinate of P - Q on E₀ (the precomp difference point chosen at
     * table-generation time). Extracted from the C reference's
     * {@code basis_even.PmQ} value at runtime via {@code fp2_encode}. The
     * canonical Java differencePoint can pick the opposite of P-Q vs P+Q,
     * which is why we use the C precomp constant directly.
     */
    public static final Fp2 BASIS_E0_PmQX = new Fp2(
        new Fp(new BigInteger("0017ed1ded6dce3c56831deae1dadeabad269e104cf932fae5b7b99c0128dd27", 16)),
        new Fp(new BigInteger("03cdd6007c4f727655ecab154c6425fb0ec882078cca9770b17c2e4640d7234e", 16)));

    private static Fp2 mkFp2(long[] reLimbs, long[] imLimbs)
    {
        BigInteger[] parts = MontgomeryLvl1.fp2FromMontgomery5x51(reLimbs, imLimbs);
        return new Fp2(new Fp(parts[0]), new Fp(parts[1]));
    }

    private E0BasisLvl1()
    {
    }
}
