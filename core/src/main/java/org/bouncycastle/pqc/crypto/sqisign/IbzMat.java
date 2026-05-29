package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Helpers for fixed-size integer matrices used in the SQIsign quaternion
 * subsystem. Java port of {@code src/quaternion/ref/generic/dim4.c} and
 * {@code dim2.c}'s ibz_mat_* helpers.
 */
final class IbzMat
{
    private IbzMat()
    {
    }

    // ---- allocation ---------------------------------------------------------

    /** Allocate and zero-initialize an n×n {@link Ibz} matrix. */
    public static Ibz[][] init(int n)
    {
        Ibz[][] m = new Ibz[n][n];
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                m[i][j] = new Ibz();
            }
        }
        return m;
    }

    public static Ibz[][] init4x4()
    {
        return init(4);
    }

    public static Ibz[][] init2x2()
    {
        return init(2);
    }

    // ---- 4x4 ops ------------------------------------------------------------

    public static void copy4x4(Ibz[][] dst, Ibz[][] src)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.copy(dst[i][j], src[i][j]);
            }
        }
    }

    private static void zero4x4(Ibz[][] m)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.set(m[i][j], 0);
            }
        }
    }

    public static void identity4x4(Ibz[][] m)
    {
        zero4x4(m);
        for (int i = 0; i < 4; i++)
        {
            Ibz.set(m[i][i], 1);
        }
    }

    public static int equal4x4(Ibz[][] a, Ibz[][] b)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                if (Ibz.cmp(a[i][j], b[i][j]) != 0)
                {
                    return 0;
                }
            }
        }
        return 1;
    }

    /** {@code ibz_mat_4x4_mul}: standard 4x4 product. */
    public static void mul4x4(Ibz[][] res, Ibz[][] a, Ibz[][] b)
    {
        Ibz[][] work = init4x4();
        Ibz prod = new Ibz();
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.set(work[i][j], 0);
                for (int k = 0; k < 4; k++)
                {
                    Ibz.mul(prod, a[i][k], b[k][j]);
                    Ibz.add(work[i][j], work[i][j], prod);
                }
            }
        }
        copy4x4(res, work);
    }

    public static void transpose4x4(Ibz[][] t, Ibz[][] m)
    {
        Ibz[][] work = init4x4();
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.copy(work[i][j], m[j][i]);
            }
        }
        copy4x4(t, work);
    }

    public static void scalarMul4x4(Ibz[][] prod, Ibz scalar, Ibz[][] mat)
    {
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.mul(prod[i][j], mat[i][j], scalar);
            }
        }
    }

    /** {@code ibz_mat_4x4_scalar_div}: returns 1 iff scalar divides all entries. */
    public static int scalarDiv4x4(Ibz[][] quot, Ibz scalar, Ibz[][] mat)
    {
        int r = 1;
        Ibz rem = new Ibz();
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.div(quot[i][j], rem, mat[i][j], scalar);
                r &= Ibz.isZero(rem);
            }
        }
        return r;
    }

    /**
     * 3x3 determinant of a submatrix specified by a 3-element row/column index
     * set. Internal helper for {@link #invWithDetAsDenom4x4}.
     */
    private static java.math.BigInteger det3x3(java.math.BigInteger[][] m,
                                               int[] rows, int[] cols)
    {
        // Cofactor expansion along row 0
        java.math.BigInteger r = java.math.BigInteger.ZERO;
        for (int j = 0; j < 3; j++)
        {
            java.math.BigInteger a = m[rows[1]][cols[(j + 1) % 3]].multiply(m[rows[2]][cols[(j + 2) % 3]]);
            java.math.BigInteger b = m[rows[1]][cols[(j + 2) % 3]].multiply(m[rows[2]][cols[(j + 1) % 3]]);
            java.math.BigInteger term = m[rows[0]][cols[j]].multiply(a.subtract(b));
            r = r.add(term);
        }
        return r;
    }

    /**
     * Computes {@code det(mat)} and (if {@code inv} is non-null) the adjugate
     * matrix scaled so that {@code adj(mat) * mat == det(mat) * I}. The
     * returned matrix is the integer adjugate; to obtain the rational inverse,
     * divide entrywise by {@code det}. Mirrors C
     * {@code ibz_mat_4x4_inv_with_det_as_denom}: returns 1 iff the matrix is
     * invertible (det != 0); when not invertible, {@code inv} is left zero.
     * <p>
     * The C reference uses a more efficient cofactor scheme via 6 stored 2x2
     * minors; this Java port uses straightforward Laplace expansion for
     * clarity. The output values must be identical for any non-singular input.
     */
    public static int invWithDetAsDenom4x4(Ibz[][] inv, Ibz det, Ibz[][] mat)
    {
        // Promote to BigInteger for easier algebra.
        java.math.BigInteger[][] m = new java.math.BigInteger[4][4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                m[i][j] = mat[i][j].v;
            }
        }

        // det via cofactor expansion along row 0.
        int[] all = {0, 1, 2, 3};
        java.math.BigInteger d = java.math.BigInteger.ZERO;
        for (int j = 0; j < 4; j++)
        {
            int[] subCols = removeAt(all, j);
            java.math.BigInteger sub = det3x3(m, new int[]{1, 2, 3}, subCols);
            java.math.BigInteger term = m[0][j].multiply(sub);
            if ((j & 1) == 0)
            {
                d = d.add(term);
            }
            else
            {
                d = d.subtract(term);
            }
        }

        if (det != null)
        {
            det.v = d;
        }

        if (inv != null)
        {
            if (d.signum() == 0)
            {
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        inv[i][j].v = java.math.BigInteger.ZERO;
                    }
                }
            }
            else
            {
                // adjugate[i][j] = (-1)^(i+j) * det(minor[j][i])
                for (int i = 0; i < 4; i++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        int[] rows = removeAt(all, j);
                        int[] cols = removeAt(all, i);
                        java.math.BigInteger cof = det3x3(m, rows, cols);
                        if (((i + j) & 1) != 0)
                        {
                            cof = cof.negate();
                        }
                        inv[i][j].v = cof;
                    }
                }
            }
        }

        return d.signum() == 0 ? 0 : 1;
    }

    private static int[] removeAt(int[] arr, int idx)
    {
        int[] out = new int[arr.length - 1];
        int k = 0;
        for (int i = 0; i < arr.length; i++)
        {
            if (i == idx)
            {
                continue;
            }
            out[k++] = arr[i];
        }
        return out;
    }

    public static void gcd4x4(Ibz gcd, Ibz[][] m)
    {
        Ibz d = m[0][0].copy();
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.gcd(d, d, m[i][j]);
            }
        }
        Ibz.copy(gcd, d);
    }

    /** {@code ibz_mat_4x4_eval}: matrix-vector product res = mat * vec. */
    public static void eval4x4(Ibz[] res, Ibz[][] mat, Ibz[] vec)
    {
        Ibz[] sum = IbzVec.init4();
        Ibz prod = new Ibz();
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.mul(prod, mat[i][j], vec[j]);
                Ibz.add(sum[i], sum[i], prod);
            }
        }
        IbzVec.copy4(res, sum);
    }

    /** {@code ibz_mat_4x4_eval_t}: res = vec * mat (transpose-equivalent). */
    public static void eval4x4T(Ibz[] res, Ibz[] vec, Ibz[][] mat)
    {
        Ibz[] sum = IbzVec.init4();
        Ibz prod = new Ibz();
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                Ibz.mul(prod, mat[j][i], vec[j]);
                Ibz.add(sum[i], sum[i], prod);
            }
        }
        IbzVec.copy4(res, sum);
    }

    /**
     * {@code quat_qf_eval}: evaluate a quadratic form res = coord^T * qf * coord.
     * Operates entirely through {@link Ibz}.
     */
    public static void qfEval(Ibz res, Ibz[][] qf, Ibz[] coord)
    {
        Ibz[] sum = IbzVec.init4();
        eval4x4(sum, qf, coord);
        Ibz prod = new Ibz();
        Ibz acc = new Ibz();
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(prod, sum[i], coord[i]);
            if (i == 0)
            {
                Ibz.copy(acc, prod);
            }
            else
            {
                Ibz.add(acc, acc, prod);
            }
        }
        Ibz.copy(res, acc);
    }

    // ---- 2x2 ops ------------------------------------------------------------

    /**
     * {@code ibz_mat_2x2_inv_mod}: invert a 2×2 integer matrix modulo
     * {@code mod}. Returns 1 on success, 0 if the determinant is not
     * coprime to {@code mod}.
     *
     * <p>For matrix M = [[a, b], [c, d]], det = a·d - b·c. The inverse is
     * (1/det) · [[d, -b], [-c, a]] mod mod.</p>
     */
    public static int invMod2x2(Ibz[][] inv, Ibz[][] mat, Ibz mod)
    {
        java.math.BigInteger a = mat[0][0].v;
        java.math.BigInteger b = mat[0][1].v;
        java.math.BigInteger c = mat[1][0].v;
        java.math.BigInteger d = mat[1][1].v;
        java.math.BigInteger m = mod.v;

        java.math.BigInteger det = a.multiply(d).subtract(b.multiply(c)).mod(m);
        java.math.BigInteger detInv;
        try
        {
            detInv = det.modInverse(m);
        }
        catch (ArithmeticException e)
        {
            return 0;
        }
        inv[0][0].v = d.multiply(detInv).mod(m);
        inv[0][1].v = m.subtract(b.mod(m)).multiply(detInv).mod(m);
        inv[1][0].v = m.subtract(c.mod(m)).multiply(detInv).mod(m);
        inv[1][1].v = a.multiply(detInv).mod(m);
        return 1;
    }

    /** {@code ibz_mat_2x2_eval}: matrix-vector product 2x2 * vec_2. */
    public static void eval2x2(Ibz[] res, Ibz[][] mat, Ibz[] vec)
    {
        Ibz a = new Ibz(), b = new Ibz();
        Ibz prod = new Ibz();

        // a = mat[0][0]*vec[0] + mat[0][1]*vec[1]
        Ibz.mul(a, mat[0][0], vec[0]);
        Ibz.mul(prod, mat[0][1], vec[1]);
        Ibz.add(a, a, prod);
        // b = mat[1][0]*vec[0] + mat[1][1]*vec[1]
        Ibz.mul(b, mat[1][0], vec[0]);
        Ibz.mul(prod, mat[1][1], vec[1]);
        Ibz.add(b, b, prod);

        Ibz.copy(res[0], a);
        Ibz.copy(res[1], b);
    }
}
