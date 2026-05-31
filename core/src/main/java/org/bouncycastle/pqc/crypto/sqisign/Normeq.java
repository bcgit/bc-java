package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;

/**
 * Norm equation solver for the SQIsign quaternion subsystem.
 * Java port of {@code src/quaternion/ref/generic/normeq.c}.
 *
 * <p>The two main entry points are:</p>
 * <ul>
 *   <li>{@link #representInteger}: finds an algebra element with a given reduced norm.</li>
 *   <li>{@link #samplingRandomIdealO0GivenNorm}: samples a random left ideal of O₀ with a prescribed norm.</li>
 * </ul>
 */
final class Normeq
{
    private Normeq()
    {
    }

    /**
     * Set the standard maximal order O₀ in the algebra of discriminant p
     * (with p ≡ 3 mod 4): basis (1, i, (i+j)/2, (1+ij)/2), denominator 2.
     * Mirrors {@code quat_lattice_O0_set}. Called transitively from
     * {@link #lattice00SetExtremal}.
     */
    public static void lattice00Set(QuatLattice o0)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.set(o0.basis[i][j], 0);
            }
        }
        Ibz.set(o0.denom, 2);
        Ibz.set(o0.basis[0][0], 2);
        Ibz.set(o0.basis[1][1], 2);
        Ibz.set(o0.basis[2][2], 1);
        Ibz.set(o0.basis[1][2], 1);
        Ibz.set(o0.basis[3][3], 1);
        Ibz.set(o0.basis[0][3], 1);
    }

    /**
     * Mirrors {@code quat_lattice_O0_set_extremal}. Used by
     * {@code ExtremalOrdersLvl1} (entry 0 only) to seed the standard extremal
     * order; lvl3 / lvl5 transcribe their entry 0 directly.
     */
    public static void lattice00SetExtremal(QuatExtremalMaximalOrder o0)
    {
        Ibz.set(o0.z.coord[1], 1);
        Ibz.set(o0.t.coord[2], 1);
        Ibz.set(o0.z.denom, 1);
        Ibz.set(o0.t.denom, 1);
        o0.q = 1;
        lattice00Set(o0.order);
    }

    /**
     * Build an algebra element from O₀-basis coefficients (x, y, z, t):
     * elem = x + z·i + (y + t·i)·j, expressed in the algebra's (1, i, j, ij) basis.
     * Mirrors {@code quat_order_elem_create}.
     */
    public static void orderElemCreate(QuatAlg.Elem elem,
                                       QuatExtremalMaximalOrder order,
                                       Ibz[] coeffs,
                                       QuatAlg algebra)
    {
        QuatAlg.Elem quatTemp = new QuatAlg.Elem();

        QuatAlg.scalar(elem, coeffs[0], Ibz.ONE);

        // quat_temp = z * coeffs[1]
        QuatAlg.scalar(quatTemp, coeffs[1], Ibz.ONE);
        QuatAlg.mul(quatTemp, order.z, quatTemp, algebra);
        QuatAlg.add(elem, elem, quatTemp);

        // quat_temp = t * coeffs[2]
        QuatAlg.scalar(quatTemp, coeffs[2], Ibz.ONE);
        QuatAlg.mul(quatTemp, order.t, quatTemp, algebra);
        QuatAlg.add(elem, elem, quatTemp);

        // quat_temp = t * coeffs[3] * z
        QuatAlg.scalar(quatTemp, coeffs[3], Ibz.ONE);
        QuatAlg.mul(quatTemp, order.t, quatTemp, algebra);
        QuatAlg.mul(quatTemp, quatTemp, order.z, algebra);
        QuatAlg.add(elem, elem, quatTemp);
    }

    /**
     * Mirrors {@code quat_represent_integer}: find γ ∈ O₀ with reduced norm
     * {@code nGamma} via random sampling + Cornacchia. Returns 1 on success
     * and writes γ to {@code gamma}.
     *
     * @param random non-null source of randomness used for the sampling loop.
     */
    public static int representInteger(QuatAlg.Elem gamma, Ibz nGamma, boolean nonDiag,
                                       QuatRepresentIntegerParams params, SecureRandom random)
    {
        if (Ibz.isEven(nGamma) == 1)
        {
            return 0;
        }
        if (nonDiag && (params.order.q % 4) != 1)
        {
            throw new IllegalArgumentException("representInteger: non_diag requires q ≡ 1 (mod 4)");
        }

        Ibz cornacchiaTarget = new Ibz();
        Ibz adjustedNGamma = new Ibz();
        Ibz q = new Ibz(params.order.q);
        Ibz bound = new Ibz();
        Ibz sqBound = new Ibz();
        Ibz temp = new Ibz();
        Ibz[] coeffs = IbzVec.init4();

        boolean standardOrder = (params.order.q == 1);

        if (nonDiag || standardOrder)
        {
            Ibz.mul(adjustedNGamma, nGamma, Ibz.TWO);
            Ibz.mul(adjustedNGamma, adjustedNGamma, Ibz.TWO);
        }
        else
        {
            Ibz.copy(adjustedNGamma, nGamma);
        }

        Ibz.div(sqBound, bound, adjustedNGamma, params.algebra.p);
        Ibz.set(temp, params.order.q);
        Ibz.sub(sqBound, sqBound, temp);
        Ibz.sqrtFloor(bound, sqBound);

        Ibz counter = new Ibz();
        Ibz.mul(temp, temp, params.algebra.p);
        Ibz.mul(temp, temp, params.algebra.p);
        Ibz.sqrtFloor(temp, temp);
        Ibz.div(counter, temp, adjustedNGamma, temp);

        boolean found = false;
        while (!found && Ibz.cmp(counter, Ibz.ZERO) != 0)
        {
            Ibz.sub(counter, counter, Ibz.ONE);

            if (Ibz.randInterval(coeffs[2], Ibz.ONE, bound, random) != 1)
            {
                return 0;
            }

            Ibz.mul(cornacchiaTarget, coeffs[2], coeffs[2]);
            Ibz.mul(temp, cornacchiaTarget, params.algebra.p);
            Ibz.sub(temp, adjustedNGamma, temp);
            Ibz.mul(sqBound, q, params.algebra.p);
            Ibz.div(temp, sqBound, temp, sqBound);
            Ibz.sqrtFloor(temp, temp);

            if (Ibz.cmp(temp, Ibz.ZERO) == 0)
            {
                continue;
            }
            if (Ibz.randInterval(coeffs[3], Ibz.ONE, temp, random) != 1)
            {
                return 0;
            }

            // cornacchia_target = n_gamma - p * (z² + q*t²)
            Ibz.mul(temp, coeffs[3], coeffs[3]);
            Ibz.mul(temp, q, temp);
            Ibz.add(cornacchiaTarget, cornacchiaTarget, temp);
            Ibz.mul(cornacchiaTarget, cornacchiaTarget, params.algebra.p);
            Ibz.sub(cornacchiaTarget, adjustedNGamma, cornacchiaTarget);
            if (Ibz.cmp(cornacchiaTarget, Ibz.ZERO) <= 0)
            {
                continue;
            }

            if (Ibz.probabPrime(cornacchiaTarget, params.primalityTestIterations) != 0)
            {
                found = Cornacchia.cornacchiaPrime(coeffs[0], coeffs[1], q, cornacchiaTarget) == 1;
            }

            if (found && nonDiag && standardOrder)
            {
                if (Ibz.isOdd(coeffs[0]) != Ibz.isOdd(coeffs[3]))
                {
                    Ibz.swap(coeffs[1], coeffs[0]);
                }
                long x = Ibz.get(coeffs[0]);
                long t = Ibz.get(coeffs[3]);
                long y = Ibz.get(coeffs[1]);
                long z = Ibz.get(coeffs[2]);
                found = (((x - t) % 4 + 4) % 4 == 2) && (((y - z) % 4 + 4) % 4 == 2);
            }

            if (found)
            {
                orderElemCreate(gamma, params.order, coeffs, params.algebra);

                // Make gamma primitive in the order; record the content in `temp`.
                QuatAlg.makePrimitive(coeffs, temp, gamma, params.order.order);

                if (nonDiag || standardOrder)
                {
                    found = Ibz.cmp(temp, Ibz.TWO) == 0;
                }
                else
                {
                    found = Ibz.cmp(temp, Ibz.ONE) == 0;
                }
            }
        }

        if (found)
        {
            // Substitute the primitive coords through the order basis matrix.
            Ibz[] tmpCoords = IbzVec.init4();
            IbzMat.eval4x4(tmpCoords, params.order.order.basis, coeffs);
            for (int i = 0; i < 4; i++)
            {
                Ibz.copy(gamma.coord[i], tmpCoords[i]);
            }
            Ibz.copy(gamma.denom, params.order.order.denom);
            return 1;
        }
        return 0;
    }

    /**
     * Sample a random left ideal of O₀ with prescribed reduced norm.
     * Mirrors {@code quat_sampling_random_ideal_O0_given_norm}.
     *
     * @param random        source of randomness for the sampling loop.
     * @param primeCofactor needed only when {@code isPrime == false}; pass
     *                      a precomputed prime so the bigger norm splits.
     */
    public static int samplingRandomIdealO0GivenNorm(QuatLeftIdeal lideal, Ibz norm, boolean isPrime,
                                                     QuatRepresentIntegerParams params, Ibz primeCofactor,
                                                     SecureRandom random)
    {
        Ibz nTemp = new Ibz();
        Ibz normD = new Ibz();
        Ibz disc = new Ibz();
        QuatAlg.Elem gen = new QuatAlg.Elem();
        QuatAlg.Elem genRerand = new QuatAlg.Elem();
        boolean found;

        if (isPrime)
        {
            found = false;
            while (!found)
            {
                Ibz.set(gen.coord[0], 0);
                Ibz.sub(nTemp, norm, Ibz.ONE);
                for (int i = 1; i < 4; i++)
                {
                    if (Ibz.randInterval(gen.coord[i], Ibz.ZERO, nTemp, random) != 1)
                    {
                        return 0;
                    }
                }

                QuatAlg.norm(nTemp, normD, gen, params.algebra);
                Ibz.neg(disc, nTemp);
                Ibz.mod(disc, disc, norm);
                int sqrtOk = Ibz.sqrtModP(gen.coord[0], disc, norm);
                found = sqrtOk == 1 && QuatAlg.isZero(gen) != 1;
            }
        }
        else
        {
            if (primeCofactor == null)
            {
                throw new IllegalArgumentException("samplingRandomIdealO0GivenNorm: prime cofactor required when isPrime == false");
            }
            if (Ibz.isZero(norm) == 1)
            {
                return 0;
            }
            Ibz.mul(nTemp, primeCofactor, norm);
            int ok = representInteger(gen, nTemp, false, params, random);
            found = ok == 1 && QuatAlg.isZero(gen) != 1;
        }

        if (!found)
        {
            return 0;
        }

        // Rerandomize the ideal class
        found = false;
        while (!found)
        {
            for (int i = 0; i < 4; i++)
            {
                if (Ibz.randInterval(genRerand.coord[i], Ibz.ONE, norm, random) != 1)
                {
                    return 0;
                }
            }
            QuatAlg.norm(nTemp, normD, genRerand, params.algebra);
            Ibz.gcd(disc, nTemp, norm);
            found = Ibz.isOne(disc) == 1 && QuatAlg.isZero(genRerand) != 1;
        }

        QuatAlg.mul(gen, gen, genRerand, params.algebra);
        QuatLeftIdeal.create(lideal, gen, norm, params.order.order, params.algebra);

        if (Ibz.cmp(norm, lideal.norm) != 0)
        {
            throw new IllegalStateException("sampling: norm mismatch");
        }
        return 1;
    }

    /**
     * Mirrors {@code quat_change_to_O0_basis}: rewrite an algebra element's
     * coordinates in the O₀ basis (1, i, (i+j)/2, (1+ij)/2). Assumes the
     * element actually lies in O₀ (the C code asserts each step is divisible
     * by the denominator).
     */
    public static void changeToO0Basis(Ibz[] vec, QuatAlg.Elem el)
    {
        Ibz tmp = new Ibz();
        // vec[2] = 2 * el.coord[2]
        Ibz.copy(vec[2], el.coord[2]);
        Ibz.add(vec[2], vec[2], vec[2]);
        // vec[3] = 2 * el.coord[3]
        Ibz.copy(vec[3], el.coord[3]);
        Ibz.add(vec[3], vec[3], vec[3]);
        // vec[0] = el.coord[0] - el.coord[3]
        Ibz.sub(vec[0], el.coord[0], el.coord[3]);
        // vec[1] = el.coord[1] - el.coord[2]
        Ibz.sub(vec[1], el.coord[1], el.coord[2]);

        for (int i = 0; i < 4; i++)
        {
            Ibz.div(vec[i], tmp, vec[i], el.denom);
        }
    }

}
