package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Hermite Normal Form reduction over the integers, modulo a fixed bound.
 * Java port of {@code src/quaternion/ref/generic/hnf/hnf.c}.
 *
 * <p>Implements algorithm 2.4.8 from Henri Cohen's "A Course in Computational
 * Algebraic Number Theory" (Springer-Verlag GTM, 1993): given a 4xN matrix
 * whose columns are integer vectors, computes its 4x4 HNF modulo a bound
 * {@code m} that must be a positive multiple of the determinant of the
 * full-rank lattice spanned by the columns.</p>
 */
final class Hnf
{
    private Hnf()
    {
    }

    // ---- vector helpers (mod m) ---------------------------------------------

    /**
     * lc = coeffA * vecA + coeffB * vecB, each component centered-mod {@code mod}.
     * Mirrors {@code ibz_vec_4_linear_combination_mod}.
     */
    private static void linearCombination4Mod(Ibz[] lc, Ibz coeffA, Ibz[] vecA, Ibz coeffB, Ibz[] vecB, Ibz mod)
    {
        Ibz prod = new Ibz();
        Ibz[] sums = IbzVec.init4();
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(sums[i], coeffA, vecA[i]);
            Ibz.mul(prod, coeffB, vecB[i]);
            Ibz.add(sums[i], sums[i], prod);
            Ibz.centeredMod(sums[i], sums[i], mod);
        }
        IbzVec.copy4(lc, sums);
    }

    /** Component-wise centered mod. Mirrors {@code ibz_vec_4_copy_mod}. */
    private static void copy4Mod(Ibz[] res, Ibz[] vec, Ibz mod)
    {
        for (int i = 0; i < 4; i++)
        {
            Ibz.centeredMod(res[i], vec[i], mod);
        }
    }

    /** Component-wise scalar mul, then Euclidean mod. Mirrors {@code ibz_vec_4_scalar_mul_mod}. */
    private static void scalarMul4Mod(Ibz[] prod, Ibz scalar, Ibz[] vec, Ibz mod)
    {
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(prod[i], vec[i], scalar);
            Ibz.mod(prod[i], prod[i], mod);
        }
    }

    // ---- core HNF algorithm -------------------------------------------------

    /**
     * Compute the 4x4 HNF of an integer 4xN generator matrix modulo a fixed
     * positive bound {@code mod}. The columns of the input
     * {@code generators[0..n-1]} are 4-vectors. {@code n} must be at least 4.
     * Mirrors C {@code ibz_mat_4xn_hnf_mod_core}.
     */
    public static void hnf4xnModCore(Ibz[][] hnf, int n, Ibz[][] generators, Ibz mod)
    {
        if (n <= 3)
        {
            throw new IllegalArgumentException("hnf4xnModCore: need n > 3");
        }
        if (Ibz.cmp(mod, Ibz.ZERO) <= 0)
        {
            throw new IllegalArgumentException("hnf4xnModCore: modulus must be positive");
        }

        Ibz[][] a = new Ibz[n][4];
        for (int h = 0; h < n; h++)
        {
            a[h] = new Ibz[4];
            for (int t = 0; t < 4; t++)
            {
                a[h][t] = generators[h][t].copy();
            }
        }
        Ibz[][] w = new Ibz[4][];
        for (int i = 0; i < 4; i++)
        {
            w[i] = IbzVec.init4();
        }

        Ibz m = mod.copy();
        Ibz d = new Ibz();
        Ibz u = new Ibz();
        Ibz v = new Ibz();
        Ibz r = new Ibz();
        Ibz q = new Ibz();
        Ibz coeff1 = new Ibz();
        Ibz coeff2 = new Ibz();
        Ibz[] c = IbzVec.init4();

        int i = 3;
        int j = n - 1;
        int k = n - 1;

        while (i != -1)
        {
            while (j != 0)
            {
                j = j - 1;
                if (Ibz.isZero(a[j][i]) != 1)
                {
                    Ibz.xgcdWithUNotZero(d, u, v, a[k][i], a[j][i]);
                    IbzVec.linearCombination4(c, u, a[k], v, a[j]);
                    Ibz.div(coeff1, r, a[k][i], d);
                    Ibz.div(coeff2, r, a[j][i], d);
                    Ibz.neg(coeff2, coeff2);
                    // Note: a[j] reads from a[j] and a[k]; build a temp.
                    Ibz[] newAj = IbzVec.init4();
                    linearCombination4Mod(newAj, coeff1, a[j], coeff2, a[k], m);
                    IbzVec.copy4(a[j], newAj);
                    // Now overwrite a[k] with c mod m.
                    copy4Mod(a[k], c, m);
                }
            }
            Ibz.xgcdWithUNotZero(d, u, v, a[k][i], m);
            scalarMul4Mod(w[i], u, a[k], m);
            if (Ibz.isZero(w[i][i]) == 1)
            {
                Ibz.copy(w[i][i], m);
            }
            for (int h = i + 1; h < 4; h++)
            {
                Ibz.divFloor(q, r, w[h][i], w[i][i]);
                Ibz.neg(q, q);
                IbzVec.linearCombination4(w[h], Ibz.ONE, w[h], q, w[i]);
            }
            Ibz.div(m, r, m, d);

            if (i != 0)
            {
                k = k - 1;
                i = i - 1;
                j = k;
                if (Ibz.isZero(a[k][i]) == 1)
                {
                    Ibz.copy(a[k][i], m);
                }
            }
            else
            {
                k = k - 1;
                i = i - 1;
                j = k;
            }
        }

        // Build HNF result: hnf[i][j] = w[j][i]
        for (int jj = 0; jj < 4; jj++)
        {
            for (int ii = 0; ii < 4; ii++)
            {
                Ibz.copy(hnf[ii][jj], w[jj][ii]);
            }
        }
    }
}
