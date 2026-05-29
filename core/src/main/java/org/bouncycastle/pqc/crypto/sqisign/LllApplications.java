package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;

/**
 * Higher-level LLL-driven operations on quaternion left ideals. Java port of
 * {@code src/quaternion/ref/generic/lll/lll_applications.c}.
 */
final class LllApplications
{
    private LllApplications()
    {
    }

    /**
     * {@code quat_lideal_reduce_basis}: produce an LLL-reduced basis of the
     * ideal lattice along with the (lower-triangular) reduced Gram matrix
     * scaled by the lattice denominator squared. Mirrors the C reference
     * including the "divide diagonals by 2 and zero the upper triangle"
     * post-processing.
     */
    public static void reduceBasis(Ibz[][] reduced, Ibz[][] gram, QuatLeftIdeal lideal, QuatAlg alg)
    {
        Ibz gramCorrector = new Ibz();
        Ibz.mul(gramCorrector, lideal.lattice.denom, lideal.lattice.denom);
        QuatLeftIdeal.classGram(gram, lideal, alg);
        IbzMat.copy4x4(reduced, lideal.lattice.basis);
        Lll.core(gram, reduced);
        IbzMat.scalarMul4x4(gram, gramCorrector, gram);
        for (int i = 0; i < 4; i++)
        {
            Ibz.div2exp(gram[i][i], gram[i][i], 1);
            for (int j = i + 1; j < 4; j++)
            {
                Ibz.set(gram[i][j], 0);
            }
        }
    }

    /**
     * {@code quat_lideal_lideal_mul_reduced}: product of two left ideals,
     * with an LLL-reduced basis written back into {@code prod.lattice.basis}
     * and the corresponding (post-processed) Gram matrix written to
     * {@code gram}. Java mirror of
     * {@code src/quaternion/ref/generic/lll/lll_applications.c}.
     *
     * <p>The {@code parent_order} of {@code prod} is set to that of
     * {@code lideal1}, mirroring the C convention.</p>
     */
    public static void lidealMulReduced(QuatLeftIdeal prod, Ibz[][] gram,
                                        QuatLeftIdeal lideal1, QuatLeftIdeal lideal2,
                                        QuatAlg alg)
    {
        Ibz[][] red = IbzMat.init4x4();
        QuatLattice.mul(prod.lattice, lideal1.lattice, lideal2.lattice, alg);
        prod.parentOrder = lideal1.parentOrder;
        QuatLeftIdeal.norm(prod);
        reduceBasis(red, gram, prod, alg);
        IbzMat.copy4x4(prod.lattice.basis, red);
    }

    /**
     * {@code quat_lideal_prime_norm_reduced_equivalent}: replace {@code lideal}
     * with an equivalent ideal of prime norm and short basis. This is the
     * second step in {@code protocols_keygen}: it shortens the secret ideal
     * to make the subsequent isogeny evaluation efficient.
     *
     * @param random            source of randomness for the linear-combination
     *                          sampling loop. Must match the C reference's
     *                          NIST DRBG draw order to reproduce KAT bytes.
     * @param primalityNumIter  Miller-Rabin iterations for the candidate norm.
     * @param equivBoundCoeff   half-range of the integer coefficients sampled
     *                          (the C reference uses 5 for lvl1).
     * @return 1 on success, 0 if the search exhausted all
     *         {@code (2 · equivBoundCoeff + 1)⁴} candidates without finding
     *         a prime-norm equivalent.
     */
    public static int primeNormReducedEquivalent(QuatLeftIdeal lideal, QuatAlg alg,
                                                 int primalityNumIter, int equivBoundCoeff,
                                                 SecureRandom random)
    {
        Ibz[][] gram = IbzMat.init4x4();
        Ibz[][] red = IbzMat.init4x4();
        reduceBasis(red, gram, lideal, alg);

        QuatAlg.Elem newAlpha = new QuatAlg.Elem();
        Ibz tmp = new Ibz();
        Ibz remainder = new Ibz();
        Ibz adjustedNorm = new Ibz();
        Ibz.mul(adjustedNorm, lideal.lattice.denom, lideal.lattice.denom);

        long limit = (2L * equivBoundCoeff + 1);
        limit *= limit;
        limit *= limit;
        if (limit > Integer.MAX_VALUE)
        {
            limit = Integer.MAX_VALUE;
        }
        int equivNumIter = (int)limit;

        for (int ctr = 0; ctr < equivNumIter; ctr++)
        {
            for (int i = 0; i < 4; i++)
            {
                if (Ibz.randIntervalMinmM(newAlpha.coord[i], equivBoundCoeff, random) != 1)
                {
                    return 0;
                }
            }
            IbzMat.qfEval(tmp, gram, newAlpha.coord);
            Ibz.div(tmp, remainder, tmp, adjustedNorm);
            if (Ibz.isZero(remainder) != 1)
            {
                // unexpected — the gram form should produce divisible norms.
                continue;
            }
            if (Ibz.probabPrime(tmp, primalityNumIter) == 0)
            {
                continue;
            }

            // Found prime: build the equivalent ideal.
            Ibz[] newCoords = IbzVec.init4();
            IbzMat.eval4x4(newCoords, red, newAlpha.coord);
            for (int i = 0; i < 4; i++)
            {
                Ibz.copy(newAlpha.coord[i], newCoords[i]);
            }
            Ibz.copy(newAlpha.denom, lideal.lattice.denom);

            QuatAlg.conj(newAlpha, newAlpha);
            Ibz.mul(newAlpha.denom, newAlpha.denom, lideal.norm);

            QuatLeftIdeal.mul(lideal, lideal, newAlpha, alg);
            return 1;
        }
        return 0;
    }
}
