package org.bouncycastle.pqc.crypto.sqisign;

/**
 * Helpers over fixed-size arrays of {@link Ibz} elements.
 * Java port of the vec_2 / vec_4 helpers from
 * {@code src/quaternion/ref/generic/dim2.c} and {@code dim4.c}.
 */
final class IbzVec
{
    private IbzVec()
    {
    }

    // ---- allocation ---------------------------------------------------------

    /** Allocate and zero-initialize an Ibz vector of length n. */
    public static Ibz[] init(int n)
    {
        Ibz[] v = new Ibz[n];
        for (int i = 0; i < n; i++)
        {
            v[i] = new Ibz();
        }
        return v;
    }

    /** {@code ibz_vec_4_init}. */
    public static Ibz[] init4()
    {
        return init(4);
    }

    // ---- 4-vector ops -------------------------------------------------------

    /** {@code ibz_vec_4_set}. */
    public static void set4(Ibz[] vec, long c0, long c1, long c2, long c3)
    {
        Ibz.set(vec[0], c0);
        Ibz.set(vec[1], c1);
        Ibz.set(vec[2], c2);
        Ibz.set(vec[3], c3);
    }

    /** {@code ibz_vec_4_copy}. */
    public static void copy4(Ibz[] dst, Ibz[] src)
    {
        for (int i = 0; i < 4; i++)
        {
            Ibz.copy(dst[i], src[i]);
        }
    }

    /** {@code ibz_vec_4_negate}. */
    public static void negate4(Ibz[] neg, Ibz[] vec)
    {
        for (int i = 0; i < 4; i++)
        {
            Ibz.neg(neg[i], vec[i]);
        }
    }

    /** {@code ibz_vec_4_add}. */
    public static void add4(Ibz[] res, Ibz[] a, Ibz[] b)
    {
        for (int i = 0; i < 4; i++)
        {
            Ibz.add(res[i], a[i], b[i]);
        }
    }

    /** {@code ibz_vec_4_sub}. */
    public static void sub4(Ibz[] res, Ibz[] a, Ibz[] b)
    {
        for (int i = 0; i < 4; i++)
        {
            Ibz.sub(res[i], a[i], b[i]);
        }
    }

    /** {@code ibz_vec_4_is_zero}. */
    public static int isZero4(Ibz[] x)
    {
        int r = 1;
        for (int i = 0; i < 4; i++)
        {
            r &= Ibz.isZero(x[i]);
        }
        return r;
    }

    /** {@code ibz_vec_4_scalar_mul}. */
    public static void scalarMul4(Ibz[] prod, Ibz scalar, Ibz[] vec)
    {
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(prod[i], vec[i], scalar);
        }
    }

    /**
     * {@code ibz_vec_4_scalar_div}: divide each component by {@code scalar}
     * using truncated division. Returns 1 iff the scalar divides every
     * component exactly (so {@code prod * scalar == vec}); 0 otherwise.
     */
    public static int scalarDiv4(Ibz[] quot, Ibz scalar, Ibz[] vec)
    {
        int r = 1;
        Ibz rem = new Ibz();
        for (int i = 0; i < 4; i++)
        {
            Ibz.div(quot[i], rem, vec[i], scalar);
            r &= Ibz.isZero(rem);
        }
        return r;
    }

    /** {@code ibz_vec_4_content}: GCD of all four components. */
    public static void content4(Ibz content, Ibz[] v)
    {
        Ibz.gcd(content, v[0], v[1]);
        Ibz.gcd(content, v[2], content);
        Ibz.gcd(content, v[3], content);
    }

    /** {@code ibz_vec_4_linear_combination}: lc = coeff_a * vec_a + coeff_b * vec_b. */
    public static void linearCombination4(Ibz[] lc, Ibz coeffA, Ibz[] vecA, Ibz coeffB, Ibz[] vecB)
    {
        Ibz prod = new Ibz();
        Ibz[] sums = init4();
        for (int i = 0; i < 4; i++)
        {
            Ibz.mul(sums[i], coeffA, vecA[i]);
            Ibz.mul(prod, coeffB, vecB[i]);
            Ibz.add(sums[i], sums[i], prod);
        }
        copy4(lc, sums);
    }

    // ---- 2-vector ops -------------------------------------------------------

}
