package org.bouncycastle.pqc.crypto.sqisign;


/**
 * Level-independent helpers from {@code src/id2iso/ref/lvlx/id2iso.c}:
 * scalar-mul with {@link Ibz}-stored scalars and the matrix application onto
 * a 2^f-torsion basis.
 *
 * <p>The deeper id2iso functions (ideal_to_kernel_dlogs_even,
 * kernel_dlogs_to_ideal_even, endomorphism_application_even_basis,
 * change_of_basis_matrix_tate) depend on the precomp tables
 * {@code ACTION_GEN2/3/4/J/I}, {@code EXTREMAL_ORDERS},
 * {@code CURVES_WITH_ENDOMORPHISMS}, and {@code QUATALG_PINFTY}, and on
 * {@code ec_dlog_2_tate} which is itself blocked on precomp; they will land
 * once the precomp tables are regenerated.</p>
 */
final class Id2IsoHelpers
{
    private Id2IsoHelpers()
    {
    }

    /**
     * {@code ec_biscalar_mul_ibz_vec}: scalar mul [x]·P + [y]·Q where x and y
     * are stored as a length-2 {@link Ibz} vector and P, Q are an
     * (X : Z)-basis of the 2^f-torsion subgroup.
     */
    public static int ecBiscalarMulIbzVec(EcPoint res, Ibz[] scalarVec, int f,
                                          EcBasis PQ, EcCurve curve)
    {
        return EcBiLadder.biscalarMul(res, scalarVec[0].v, scalarVec[1].v, f, PQ, curve);
    }

    /**
     * {@code matrix_application_even_basis}: apply a 2×2 integer matrix
     * (mod 2^f) to a 2^f-torsion basis (P, Q, P-Q), in place.
     *
     * <p>For matrix {@code [[a, c], [b, d]]} the result is</p>
     * <ul>
     *   <li>{@code P' = a·P + b·Q}</li>
     *   <li>{@code Q' = c·P + d·Q}</li>
     *   <li>{@code P' - Q' = (a-c)·P + (b-d)·Q}</li>
     * </ul>
     *
     * @return 1 on success, 0 if the biscalar-mul rejected the input
     *         (returned by the final {@code ec_biscalar_mul}).
     */
    public static int matrixApplicationEvenBasis(EcBasis bas, EcCurve E, Ibz[][] mat, int f)
    {
        java.math.BigInteger powTwo = java.math.BigInteger.ONE.shiftLeft(f);

        // Reduce matrix entries mod 2^f.
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                mat[i][j].v = mat[i][j].v.mod(powTwo);
            }
        }

        EcBasis tmpBas = new EcBasis();
        EcBasis.copy(tmpBas, bas);

        // P' = mat[0][0]·P + mat[1][0]·Q
        EcBiLadder.biscalarMul(bas.P, mat[0][0].v, mat[1][0].v, f, tmpBas, E);
        // Q' = mat[0][1]·P + mat[1][1]·Q
        EcBiLadder.biscalarMul(bas.Q, mat[0][1].v, mat[1][1].v, f, tmpBas, E);
        // (P' - Q') = (mat[0][0] - mat[0][1])·P + (mat[1][0] - mat[1][1])·Q
        java.math.BigInteger aMinusC = mat[0][0].v.subtract(mat[0][1].v).mod(powTwo);
        java.math.BigInteger bMinusD = mat[1][0].v.subtract(mat[1][1].v).mod(powTwo);
        return EcBiLadder.biscalarMul(bas.PmQ, aMinusC, bMinusD, f, tmpBas, E);
    }

    /**
     * {@code endomorphism_application_even_basis}: apply an endomorphism
     * {@code theta} of a special curve E (specified via its
     * endomorphism-action data) to the 2^f-torsion basis {@code bas}.
     *
     * <p>Java mirror of {@code endomorphism_application_even_basis} from
     * {@code src/id2iso/ref/lvlx/id2iso.c}. The C reference looks up
     * {@code EXTREMAL_ORDERS[index_alternate_curve]} and
     * {@code CURVES_WITH_ENDOMORPHISMS[index_alternate_curve]} from precomp
     * tables; this overload takes them as explicit parameters so the helper
     * is callable today, before the precomp transcription lands.</p>
     *
     * <p>The decomposition is: {@code theta = content · (c0·1 + c1·gen2 + c2·gen3 + c3·gen4)}
     * with respect to the {@code order} basis. The resulting 2×2 action
     * matrix is</p>
     * <pre>
     *   M[i][j] = content · ( δ_ij · c0
     *                       + c1 · actionGen2[i][j]
     *                       + c2 · actionGen3[i][j]
     *                       + c3 · actionGen4[i][j] )
     * </pre>
     * <p>followed by {@link #matrixApplicationEvenBasis} on {@code (bas, E, M, f)}.</p>
     *
     * @param bas         in/out: the 2^f-torsion basis to act on.
     * @param E           curve on which {@code bas} lives.
     * @param theta       endomorphism to apply (must be primitive in {@code order}
     *                    up to {@code content}, i.e., {@code content} odd).
     * @param f           torsion exponent (bases work mod 2^f).
     * @param order       parent order whose generators are referenced by
     *                    {@code actionGen2/3/4}; must contain {@code theta}.
     * @param actionGen2  2×2 matrix encoding the action of {@code order}'s
     *                    second generator on the basis.
     * @param actionGen3  2×2 matrix for the third generator.
     * @param actionGen4  2×2 matrix for the fourth generator.
     * @return 1 on success, 0 if the final biscalar-mul rejected.
     */
    public static int endomorphismApplicationEvenBasis(EcBasis bas, EcCurve E,
                                                       QuatAlg.Elem theta, int f,
                                                       QuatLattice order,
                                                       Ibz[][] actionGen2,
                                                       Ibz[][] actionGen3,
                                                       Ibz[][] actionGen4)
    {
        Ibz[] coeffs = IbzVec.init4();
        Ibz content = new Ibz();
        QuatAlg.makePrimitive(coeffs, content, theta, order);
        if (!(content.v.testBit(0)))
        {
            // The C reference asserts that `content` is odd, since otherwise
            // the matrix application after reduction mod 2^f drops too many
            // bits. Surface as a soft failure to give callers a chance to
            // recover by re-sampling.
            return 0;
        }

        Ibz[][] mat = new Ibz[2][2];
        for (int i = 0; i < 2; i++)
        {
            for (int j = 0; j < 2; j++)
            {
                mat[i][j] = new Ibz();
            }
        }

        Ibz tmp = new Ibz();
        for (int i = 0; i < 2; i++)
        {
            // diagonal contribution from c0 · I
            Ibz.add(mat[i][i], mat[i][i], coeffs[0]);
            for (int j = 0; j < 2; j++)
            {
                Ibz.mul(tmp, actionGen2[i][j], coeffs[1]);
                Ibz.add(mat[i][j], mat[i][j], tmp);
                Ibz.mul(tmp, actionGen3[i][j], coeffs[2]);
                Ibz.add(mat[i][j], mat[i][j], tmp);
                Ibz.mul(tmp, actionGen4[i][j], coeffs[3]);
                Ibz.add(mat[i][j], mat[i][j], tmp);
                Ibz.mul(mat[i][j], mat[i][j], content);
            }
        }

        return matrixApplicationEvenBasis(bas, E, mat, f);
    }

    /**
     * {@code id2iso_kernel_dlogs_to_ideal_even}: compute the left ideal of
     * O₀ whose corresponding isogeny has kernel {@code vec2[0]·B₀[0] + vec2[1]·B₀[1]}
     * on E₀'s 2^f-torsion basis.
     *
     * <p>Java mirror of {@code id2iso_kernel_dlogs_to_ideal_even} from
     * {@code src/id2iso/ref/lvlx/id2iso.c}. Uses the {@code ACTION_J},
     * {@code ACTION_GEN4}, {@code ACTION_I} matrices from
     * {@code CURVES_WITH_ENDOMORPHISMS[0]}; these are now populated in
     * {@link org.bouncycastle.pqc.crypto.sqisign.EndomorphismActionLvl1}.</p>
     *
     * <p>The algorithm:</p>
     * <ol>
     *   <li>Build a 2×2 matrix M whose columns are {@code [vec2[0], vec2[1]]}
     *       and {@code ACTION_J·vec2 + ACTION_GEN4·vec2}, reduced mod 2^f.</li>
     *   <li>Invert M mod 2^f.</li>
     *   <li>Apply M^{-1} to {@code ACTION_I·vec2} to get coordinates (a, b).</li>
     *   <li>Build the ideal generator {@code (2a + b - 2i + (2b)j + b·k) / 2},
     *       which equals {@code a - i + b·(j + (1+k)/2)}.</li>
     *   <li>Build the ideal as {@code O₀ · gen + O₀ · 2^f}.</li>
     * </ol>
     *
     * @param lideal      output: the constructed left ideal of norm 2^f.
     * @param vec2        the length-2 ibz vector encoding the kernel generator.
     * @param f           torsion exponent (basis lives in E₀[2^f]).
     * @param actionI     {@code ACTION_I} = action of i on the basis.
     * @param actionJ     {@code ACTION_J} = action of j.
     * @param actionGen4  {@code ACTION_GEN4} = action of the order's 4th generator.
     * @param order       parent order (O₀).
     * @param alg         quaternion algebra.
     * @param torsionPlus2Power  {@code TORSION_PLUS_2POWER}, used when
     *                           {@code f == TORSION_EVEN_POWER} to avoid
     *                           recomputing the power of 2.
     * @param torsionEvenPower   {@code TORSION_EVEN_POWER}.
     */
    public static void kernelDlogsToIdealEven(
        org.bouncycastle.pqc.crypto.sqisign.QuatLeftIdeal lideal,
        Ibz[] vec2, int f,
        Ibz[][] actionI, Ibz[][] actionJ, Ibz[][] actionGen4,
        QuatLattice order,
        org.bouncycastle.pqc.crypto.sqisign.QuatAlg alg,
        Ibz torsionPlus2Power, int torsionEvenPower)
    {
        Ibz twoPow = new Ibz();
        if (f == torsionEvenPower)
        {
            Ibz.copy(twoPow, torsionPlus2Power);
        }
        else
        {
            twoPow.v = java.math.BigInteger.ONE.shiftLeft(f);
        }

        Ibz[] vec = IbzVec.init4();   // we only use slots [0], [1] for length-2 vectors
        Ibz[][] mat = org.bouncycastle.pqc.crypto.sqisign.IbzMat.init2x2();

        // mat[*][0] = vec2 directly.
        Ibz.copy(mat[0][0], vec2[0]);
        Ibz.copy(mat[1][0], vec2[1]);

        // mat[*][1] = ACTION_J · vec2.
        Ibz[] tmpVec2 = new Ibz[]{new Ibz(), new Ibz()};
        org.bouncycastle.pqc.crypto.sqisign.IbzMat.eval2x2(tmpVec2, actionJ, vec2);
        Ibz.copy(mat[0][1], tmpVec2[0]);
        Ibz.copy(mat[1][1], tmpVec2[1]);

        // mat[*][1] += ACTION_GEN4 · vec2.
        org.bouncycastle.pqc.crypto.sqisign.IbzMat.eval2x2(tmpVec2, actionGen4, vec2);
        Ibz.add(mat[0][1], mat[0][1], tmpVec2[0]);
        Ibz.add(mat[1][1], mat[1][1], tmpVec2[1]);

        // Reduce mod 2^f.
        mat[0][1].v = mat[0][1].v.mod(twoPow.v);
        mat[1][1].v = mat[1][1].v.mod(twoPow.v);

        // Invert mat mod 2^f.
        Ibz[][] inv = org.bouncycastle.pqc.crypto.sqisign.IbzMat.init2x2();
        int invOk = org.bouncycastle.pqc.crypto.sqisign.IbzMat.invMod2x2(inv, mat, twoPow);
        if (invOk != 1)
        {
            throw new IllegalStateException(
                "kernelDlogsToIdealEven: 2x2 matrix not invertible mod 2^f");
        }

        // vec = inv · (ACTION_I · vec2).
        org.bouncycastle.pqc.crypto.sqisign.IbzMat.eval2x2(tmpVec2, actionI, vec2);
        org.bouncycastle.pqc.crypto.sqisign.IbzMat.eval2x2(tmpVec2, inv, tmpVec2);

        // Build gen = (a - i + b·(j + (1+k)/2)) with denom 2:
        //   numerator coords = (2a + b, -2, 2b, b)
        org.bouncycastle.pqc.crypto.sqisign.QuatAlg.Elem gen =
            new org.bouncycastle.pqc.crypto.sqisign.QuatAlg.Elem();
        Ibz.set(gen.denom, 2);
        Ibz.add(gen.coord[0], tmpVec2[0], tmpVec2[0]);
        Ibz.set(gen.coord[1], -2);
        Ibz.add(gen.coord[2], tmpVec2[1], tmpVec2[1]);
        Ibz.copy(gen.coord[3], tmpVec2[1]);
        Ibz.add(gen.coord[0], gen.coord[0], tmpVec2[1]);

        org.bouncycastle.pqc.crypto.sqisign.QuatLeftIdeal
            .create(lideal, gen, twoPow, order, alg);

        // C asserts norm == 2^f; we surface mismatch as IllegalStateException.
        if (Ibz.cmp(lideal.norm, twoPow) != 0)
        {
            throw new IllegalStateException(
                "kernelDlogsToIdealEven: norm mismatch — expected 2^" + f
                + ", got " + lideal.norm.v);
        }

        // Silence unused-warning on `vec`.
        Ibz.set(vec[0], 0);
    }

    /**
     * {@code id2iso_ideal_to_kernel_dlogs_even}: given a left ideal of O₀
     * whose norm is a power of 2, compute scalars {@code (s0, s1)} that
     * encode the kernel of the associated isogeny as
     * {@code s0·B₀[0] + s1·B₀[1]} on E₀'s 2^f-torsion basis.
     *
     * <p>Inverse direction of {@link #kernelDlogsToIdealEven}. Java mirror
     * of the C function in {@code src/id2iso/ref/lvlx/id2iso.c}.</p>
     *
     * @param vec         output: length-2 ibz vector (s0, s1).
     * @param lideal      input: left ideal of O₀ with 2-power norm.
     * @param actionGen2  action of the order's 2nd generator on the basis.
     * @param actionGen3  action of the 3rd generator.
     * @param actionGen4  action of the 4th generator.
     * @param alg         quaternion algebra.
     */
    public static void idealToKernelDlogsEven(Ibz[] vec,
                                              org.bouncycastle.pqc.crypto.sqisign.QuatLeftIdeal lideal,
                                              Ibz[][] actionGen2,
                                              Ibz[][] actionGen3,
                                              Ibz[][] actionGen4,
                                              org.bouncycastle.pqc.crypto.sqisign.QuatAlg alg)
    {
        // Build the matrix of (dual of α) acting on the 2^f-torsion.
        org.bouncycastle.pqc.crypto.sqisign.QuatAlg.Elem alpha =
            new org.bouncycastle.pqc.crypto.sqisign.QuatAlg.Elem();
        int genOk = org.bouncycastle.pqc.crypto.sqisign.QuatLeftIdeal.generator(
            alpha, lideal, alg);
        if (genOk != 1)
        {
            throw new IllegalStateException("idealToKernelDlogsEven: no generator found");
        }
        org.bouncycastle.pqc.crypto.sqisign.QuatAlg.conj(alpha, alpha);

        // coeffs[0..3] = α in the O₀ basis (1, gen2, gen3, gen4).
        Ibz[] coeffs = IbzVec.init4();
        org.bouncycastle.pqc.crypto.sqisign.Normeq.changeToO0Basis(coeffs, alpha);

        Ibz[][] mat = org.bouncycastle.pqc.crypto.sqisign.IbzMat.init2x2();
        Ibz tmp = new Ibz();
        for (int i = 0; i < 2; i++)
        {
            // diagonal contribution from coeffs[0] · I
            Ibz.add(mat[i][i], mat[i][i], coeffs[0]);
            for (int j = 0; j < 2; j++)
            {
                Ibz.mul(tmp, actionGen2[i][j], coeffs[1]);
                Ibz.add(mat[i][j], mat[i][j], tmp);
                Ibz.mul(tmp, actionGen3[i][j], coeffs[2]);
                Ibz.add(mat[i][j], mat[i][j], tmp);
                Ibz.mul(tmp, actionGen4[i][j], coeffs[3]);
                Ibz.add(mat[i][j], mat[i][j], tmp);
            }
        }

        // Find the kernel of α modulo lideal.norm. The C code mods both
        // columns and picks the column whose gcd with the other isn't even.
        Ibz norm = lideal.norm;
        vec[0].v = mat[0][0].v.mod(norm.v);
        vec[1].v = mat[1][0].v.mod(norm.v);
        Ibz gcd = new Ibz();
        Ibz.gcd(gcd, vec[0], vec[1]);
        if (!gcd.v.testBit(0))
        {
            vec[0].v = mat[0][1].v.mod(norm.v);
            vec[1].v = mat[1][1].v.mod(norm.v);
        }
    }
}
