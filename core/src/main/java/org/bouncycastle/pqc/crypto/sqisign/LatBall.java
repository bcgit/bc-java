package org.bouncycastle.pqc.crypto.sqisign;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Lattice ball sampling. Java port of
 * {@code src/quaternion/ref/generic/lat_ball.c}.
 *
 * <p>Two public entry points:</p>
 * <ul>
 *   <li>{@link #boundParallelogram} — computes a bounding parallelogram for
 *       a ball in the lattice, using LLL on the dual lattice.</li>
 *   <li>{@link #sampleFromBall} — rejection-samples a lattice element of
 *       norm ≤ {@code radius}.</li>
 * </ul>
 *
 * <p>Used by the sign-side {@code sample_response} helper.</p>
 */
final class LatBall
{
    private LatBall()
    {
    }

    /**
     * {@code quat_lattice_bound_parallelogram}: compute a bounding
     * parallelogram for the ball of radius {@code radius} in the lattice
     * whose Gram matrix is {@code G}.
     *
     * <p>The output {@code box} stores the half-widths along each
     * coordinate axis (in the LLL-reduced dual basis), and {@code U} is the
     * unimodular transformation matrix mapping integer-grid points to
     * lattice-element coordinates.</p>
     *
     * @param box     output: length-4 vector of integer half-widths.
     * @param U       output: 4×4 integer unimodular matrix.
     * @param G       input:  Gram matrix of the lattice.
     * @param radius  input:  squared radius (positive).
     * @return 1 if the parallelogram is non-trivial (i.e. contains more
     *         than the origin); 0 otherwise.
     */
    public static int boundParallelogram(Ibz[] box, Ibz[][] U, Ibz[][] G, Ibz radius)
    {
        Ibz denom = new Ibz();
        Ibz rem = new Ibz();
        Ibz[][] dualG = IbzMat.init4x4();

        // dualG := G^{-1} · denom. (denom is set to det(G) up to sign.)
        IbzMat.invWithDetAsDenom4x4(dualG, denom, G);

        // Initialize U = I and reduce dualG via LLL.
        IbzMat.identity4x4(U);
        Lll.core(dualG, U);

        // box[i] = floor(sqrt(dualG[i][i] · radius / denom))
        int trivial = 1;
        Ibz tmp = new Ibz();
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(tmp, dualG[i][i], radius);
            Ibz.div(box[i], rem, tmp, denom);
            Ibz.sqrtFloor(box[i], box[i]);
            if (Ibz.isZero(box[i]) == 0)
            {
                trivial = 0;
            }
        }

        // Compute the transpose transformation matrix: U := det(U) · U^{-1}.
        // U is unimodular so det(U) = ±1.
        IbzMat.invWithDetAsDenom4x4(U, denom, U);
        IbzMat.scalarMul4x4(U, denom, U);

        return (trivial == 1) ? 0 : 1;
    }

    /**
     * {@code quat_lattice_sample_from_ball}: rejection-sample a non-zero
     * algebra element {@code res} from the lattice whose squared norm is
     * at most {@code radius}.
     *
     * @param res      output: the sampled element.
     * @param lattice  input: the lattice (basis + denom).
     * @param alg      quaternion algebra.
     * @param radius   positive squared-radius bound.
     * @param random   source of randomness for the rejection loop.
     * @return 1 on success, 0 if the bounding parallelogram was trivial or
     *         the random-interval sampling failed.
     */
    public static int sampleFromBall(QuatAlg.Elem res, QuatLattice lattice,
                                     QuatAlg alg, Ibz radius, SecureRandom random)
    {
        if (radius.v.signum() <= 0)
        {
            throw new IllegalArgumentException("sampleFromBall: radius must be positive");
        }

        Ibz[] box = IbzVec.init4();
        Ibz[][] U = IbzMat.init4x4();
        Ibz[][] G = IbzMat.init4x4();
        Ibz[] x = IbzVec.init4();
        Ibz rad = new Ibz();
        Ibz tmp = new Ibz();

        QuatLattice.gram(G, lattice, alg);

        // Correct ball radius by the denominator squared and by 2 (the Gram
        // matrix encodes twice the norm).
        Ibz.mul(rad, radius, lattice.denom);
        Ibz.mul(rad, rad, lattice.denom);
        Ibz.add(rad, rad, rad);   // ×2

        int ok = boundParallelogram(box, U, G, rad);
        if (ok == 0)
        {
            return 0;
        }

        // Rejection sampling loop.
        Ibz zero = Ibz.ZERO;
        // Cap the inner loop so a pathological lattice doesn't hang the
        // sampler; mirrors the C reference's printout (debug-only there).
        int maxAttempts = 1 << 20;
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            for (int i = 0; i < 4; i++)
            {
                if (Ibz.isZero(box[i]) == 1)
                {
                    Ibz.copy(x[i], zero);
                }
                else
                {
                    Ibz two = new Ibz();
                    Ibz.add(two, box[i], box[i]);
                    int randOk = Ibz.randInterval(x[i], zero, two, random);
                    if (randOk != 1)
                    {
                        return 0;
                    }
                    Ibz.sub(x[i], x[i], box[i]);
                }
            }

            // Map x through U (transpose-eval semantics, mirroring the C
            // reference's ibz_mat_4x4_eval_t).
            Ibz[] xMapped = IbzVec.init4();
            IbzMat.eval4x4T(xMapped, x, U);
            for (int i = 0; i < 4; i++)
            {
                Ibz.copy(x[i], xMapped[i]);
            }

            // Evaluate the quadratic form.
            IbzMat.qfEval(tmp, G, x);

            // Accept if 0 < tmp <= rad.
            if (Ibz.isZero(tmp) == 1)
            {
                continue;
            }
            if (Ibz.cmp(tmp, rad) > 0)
            {
                continue;
            }

            // Found: res := lattice.basis · x  (denom: lattice.denom).
            Ibz[] coord = IbzVec.init4();
            IbzMat.eval4x4(coord, lattice.basis, x);
            for (int i = 0; i < 4; i++)
            {
                Ibz.copy(res.coord[i], coord[i]);
            }
            Ibz.copy(res.denom, lattice.denom);
            QuatAlg.normalize(res);
            return 1;
        }

        // Exhausted attempts.
        return 0;
    }
}
