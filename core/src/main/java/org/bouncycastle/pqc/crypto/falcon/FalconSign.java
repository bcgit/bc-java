package org.bouncycastle.pqc.crypto.falcon;

class FalconSign
{

    FPREngine fpr;
    FalconFFT fft;
    FalconCommon common;

    FalconSign()
    {
        this.fpr = new FPREngine();
        this.fft = new FalconFFT();
        this.common = new FalconCommon();
    }

    private static int MKN(int logn)
    {
        return 1 << logn;
    }

    /*
     * Binary case:
     *   N = 2^logn
     *   phi = X^N+1
     */

    /*
     * Get the size of the LDL tree for an input with polynomials of size
     * 2^logn. The size is expressed in the number of elements.
     */
    int ffLDL_treesize(int logn)
    {
        /*
         * For logn = 0 (polynomials are constant), the "tree" is a
         * single element. Otherwise, the tree node has size 2^logn, and
         * has two child trees for size logn-1 each. Thus, treesize s()
         * must fulfill these two relations:
         *
         *   s(0) = 1
         *   s(logn) = (2^logn) + 2*s(logn-1)
         */
        return (logn + 1) << logn;
    }

    /*
     * Inner function for ffLDL_fft(). It expects the matrix to be both
     * auto-adjoint and quasicyclic; also, it uses the source operands
     * as modifiable temporaries.
     *
     * tmp[] must have room for at least one polynomial.
     */
    void ffLDL_fft_inner(FalconFPR[] srctree, int tree,
                         FalconFPR[] srcg0, int g0, FalconFPR[] srcg1, int g1,
                         int logn, FalconFPR[] srctmp, int tmp)
    {
        int n, hn;

        n = MKN(logn);
        if (n == 1)
        {
            srctree[tree + 0] = srcg0[g0 + 0];
            return;
        }
        hn = n >> 1;

        /*
         * The LDL decomposition yields L (which is written in the tree)
         * and the diagonal of D. Since d00 = g0, we just write d11
         * into tmp.
         */
        fft.poly_LDLmv_fft(srctmp, tmp, srctree, tree, srcg0, g0, srcg1, g1, srcg0, g0, logn);

        /*
         * Split d00 (currently in g0) and d11 (currently in tmp). We
         * reuse g0 and g1 as temporary storage spaces:
         *   d00 splits into g1, g1+hn
         *   d11 splits into g0, g0+hn
         */
        fft.poly_split_fft(srcg1, g1, srcg1, g1 + hn, srcg0, g0, logn);
        fft.poly_split_fft(srcg0, g0, srcg0, g0 + hn, srctmp, tmp, logn);

        /*
         * Each split result is the first row of a new auto-adjoint
         * quasicyclic matrix for the next recursive step.
         */
        ffLDL_fft_inner(srctree, tree + n,
            srcg1, g1, srcg1, g1 + hn, logn - 1, srctmp, tmp);
        ffLDL_fft_inner(srctree, tree + n + ffLDL_treesize(logn - 1),
            srcg0, g0, srcg0, g0 + hn, logn - 1, srctmp, tmp);
    }

    /*
     * Compute the ffLDL tree of an auto-adjoint matrix G. The matrix
     * is provided as three polynomials (FFT representation).
     *
     * The "tree" array is filled with the computed tree, of size
     * (logn+1)*(2^logn) elements (see ffLDL_treesize()).
     *
     * Input arrays MUST NOT overlap, except possibly the three unmodified
     * arrays g00, g01 and g11. tmp[] should have room for at least three
     * polynomials of 2^logn elements each.
     */
    void ffLDL_fft(FalconFPR[] srctree, int tree, FalconFPR[] srcg00, int g00,
                   FalconFPR[] srcg01, int g01, FalconFPR[] srcg11, int g11,
                   int logn, FalconFPR[] srctmp, int tmp)
    {
        int n, hn;
        int d00, d11;

        n = MKN(logn);
        if (n == 1)
        {
            srctree[tree + 0] = srcg00[g00 + 0];
            return;
        }
        hn = n >> 1;
        d00 = tmp;
        d11 = tmp + n;
        tmp += n << 1;

//        memcpy(d00, g00, n * sizeof *g00);
        System.arraycopy(srcg00, g00, srctmp, d00, n);
        fft.poly_LDLmv_fft(srctmp, d11, srctree, tree, srcg00, g00, srcg01, g01, srcg11, g11, logn);

        fft.poly_split_fft(srctmp, tmp, srctmp, tmp + hn, srctmp, d00, logn);
        fft.poly_split_fft(srctmp, d00, srctmp, d00 + hn, srctmp, d11, logn);
//        memcpy(d11, tmp, n * sizeof *tmp);
        System.arraycopy(srctmp, tmp, srctmp, d11, n);
        ffLDL_fft_inner(srctree, tree + n,
            srctmp, d11, srctmp, d11 + hn, logn - 1, srctmp, tmp);
        ffLDL_fft_inner(srctree, tree + n + ffLDL_treesize(logn - 1),
            srctmp, d00, srctmp, d00 + hn, logn - 1, srctmp, tmp);
    }

    /*
     * Normalize an ffLDL tree: each leaf of value x is replaced with
     * sigma / sqrt(x).
     */
    void ffLDL_binary_normalize(FalconFPR[] srctree, int tree, int orig_logn, int logn)
    {
        /*
         * TODO: make an iterative version.
         */
        int n;

        n = MKN(logn);
        if (n == 1)
        {
            /*
             * We actually store in the tree leaf the inverse of
             * the value mandated by the specification: this
             * saves a division both here and in the sampler.
             */
            srctree[tree + 0] = fpr.fpr_mul(fpr.fpr_sqrt(srctree[tree + 0]), fpr.fpr_inv_sigma[orig_logn]);
        }
        else
        {
            ffLDL_binary_normalize(srctree, tree + n, orig_logn, logn - 1);
            ffLDL_binary_normalize(srctree, tree + n + ffLDL_treesize(logn - 1),
                orig_logn, logn - 1);
        }
    }

    /* =================================================================== */

    /*
     * Convert an integer polynomial (with small values) into the
     * representation with complex numbers.
     */
    void smallints_to_fpr(FalconFPR[] srcr, int r, byte[] srct, int t, int logn)
    {
        int n, u;

        n = MKN(logn);
        for (u = 0; u < n; u++)
        {
            srcr[r + u] = fpr.fpr_of(srct[t + u]); // t is signed
        }
    }

    /*
     * The expanded private key contains:
     *  - The B0 matrix (four elements)
     *  - The ffLDL tree
     */

    int skoff_b00(int logn)
    {
//        (void)logn;
        return 0;
    }

    int skoff_b01(int logn)
    {
        return MKN(logn);
    }

    int skoff_b10(int logn)
    {
        return 2 * MKN(logn);
    }

    int skoff_b11(int logn)
    {
        return 3 * MKN(logn);
    }

    int skoff_tree(int logn)
    {
        return 4 * MKN(logn);
    }

    /* see inner.h */
    void expand_privkey(FalconFPR[] srcexpanded_key, int expanded_key,
                        byte[] srcf, int f, byte[] srcg, int g,
                        byte[] srcF, int F, byte[] srcG, int G,
                        int logn, FalconFPR[] srctmp, int tmp)
    {
        int n;
        int rf, rg, rF, rG;
        int b00, b01, b10, b11;
        int g00, g01, g11, gxx;
        int tree;

        n = MKN(logn);
        b00 = expanded_key + skoff_b00(logn);
        b01 = expanded_key + skoff_b01(logn);
        b10 = expanded_key + skoff_b10(logn);
        b11 = expanded_key + skoff_b11(logn);
        tree = expanded_key + skoff_tree(logn);

        /*
         * We load the private key elements directly into the B0 matrix,
         * since B0 = [[g, -f], [G, -F]].
         */
        rf = b01;
        rg = b00;
        rF = b11;
        rG = b10;

        smallints_to_fpr(srcexpanded_key, rf, srcf, f, logn);
        smallints_to_fpr(srcexpanded_key, rg, srcg, g, logn);
        smallints_to_fpr(srcexpanded_key, rF, srcF, F, logn);
        smallints_to_fpr(srcexpanded_key, rG, srcG, G, logn);

        /*
         * Compute the FFT for the key elements, and negate f and F.
         */
        fft.FFT(srcexpanded_key, rf, logn);
        fft.FFT(srcexpanded_key, rg, logn);
        fft.FFT(srcexpanded_key, rF, logn);
        fft.FFT(srcexpanded_key, rG, logn);
        fft.poly_neg(srcexpanded_key, rf, logn);
        fft.poly_neg(srcexpanded_key, rF, logn);

        /*
         * The Gram matrix is G = B·B*. Formulas are:
         *   g00 = b00*adj(b00) + b01*adj(b01)
         *   g01 = b00*adj(b10) + b01*adj(b11)
         *   g10 = b10*adj(b00) + b11*adj(b01)
         *   g11 = b10*adj(b10) + b11*adj(b11)
         *
         * For historical reasons, this implementation uses
         * g00, g01 and g11 (upper triangle).
         */
        g00 = tmp; // the b__ are in srcexpanded_key and g__ are int srctmp
        g01 = g00 + n;
        g11 = g01 + n;
        gxx = g11 + n;

//        memcpy(g00, b00, n * sizeof *b00);
        System.arraycopy(srcexpanded_key, b00, srctmp, g00, n);
        fft.poly_mulselfadj_fft(srctmp, g00, logn);
//        memcpy(gxx, b01, n * sizeof *b01);
        System.arraycopy(srcexpanded_key, b01, srctmp, gxx, n);
        fft.poly_mulselfadj_fft(srctmp, gxx, logn);
        fft.poly_add(srctmp, g00, srctmp, gxx, logn);

//        memcpy(g01, b00, n * sizeof *b00);
        System.arraycopy(srcexpanded_key, b00, srctmp, g01, n);
        fft.poly_muladj_fft(srctmp, g01, srcexpanded_key, b10, logn);
//        memcpy(gxx, b01, n * sizeof *b01);
        System.arraycopy(srcexpanded_key, b01, srctmp, gxx, n);
        fft.poly_muladj_fft(srctmp, gxx, srcexpanded_key, b11, logn);
        fft.poly_add(srctmp, g01, srctmp, gxx, logn);

//        memcpy(g11, b10, n * sizeof *b10);
        System.arraycopy(srcexpanded_key, b10, srctmp, g11, n);
        fft.poly_mulselfadj_fft(srctmp, g11, logn);
//        memcpy(gxx, b11, n * sizeof *b11);
        System.arraycopy(srcexpanded_key, b11, srctmp, gxx, n);
        fft.poly_mulselfadj_fft(srctmp, gxx, logn);
        fft.poly_add(srctmp, g11, srctmp, gxx, logn);

        /*
         * Compute the Falcon tree.
         */
        ffLDL_fft(srcexpanded_key, tree, srctmp, g00, srctmp, g01, srctmp, g11, logn, srctmp, gxx);

        /*
         * Normalize tree.
         */
        ffLDL_binary_normalize(srcexpanded_key, tree, logn, logn);
    }

    /*
     * Perform Fast Fourier Sampling for target vector t. The Gram matrix
     * is provided (G = [[g00, g01], [adj(g01), g11]]). The sampled vector
     * is written over (t0,t1). The Gram matrix is modified as well. The
     * tmp[] buffer must have room for four polynomials.
     */
    void ffSampling_fft_dyntree(SamplerZ samp, SamplerCtx samp_ctx,
                                FalconFPR[] srct0, int t0, FalconFPR[] srct1, int t1,
                                FalconFPR[] srcg00, int g00, FalconFPR[] srcg01, int g01, FalconFPR[] srcg11, int g11,
                                int orig_logn, int logn, FalconFPR[] srctmp, int tmp)
    {
        int n, hn;
        int z0, z1;

        /*
         * Deepest level: the LDL tree leaf value is just g00 (the
         * array has length only 1 at this point); we normalize it
         * with regards to sigma, then use it for sampling.
         */
        if (logn == 0)
        {
            FalconFPR leaf;

            leaf = srcg00[g00 + 0];
            leaf = fpr.fpr_mul(fpr.fpr_sqrt(leaf), fpr.fpr_inv_sigma[orig_logn]);
            srct0[t0 + 0] = fpr.fpr_of(samp.sample(samp_ctx, srct0[t0 + 0], leaf));
            srct1[t1 + 0] = fpr.fpr_of(samp.sample(samp_ctx, srct1[t1 + 0], leaf));
            return;
        }

        n = 1 << logn;
        hn = n >> 1;

        /*
         * Decompose G into LDL. We only need d00 (identical to g00),
         * d11, and l10; we do that in place.
         */
        fft.poly_LDL_fft(srcg00, g00, srcg01, g01, srcg11, g11, logn);

        /*
         * Split d00 and d11 and expand them into half-size quasi-cyclic
         * Gram matrices. We also save l10 in tmp[].
         */
        fft.poly_split_fft(srctmp, tmp, srctmp, tmp + hn, srcg00, g00, logn);
//        memcpy(g00, tmp, n * sizeof *tmp);
        System.arraycopy(srctmp, tmp, srcg00, g00, n);
        fft.poly_split_fft(srctmp, tmp, srctmp, tmp + hn, srcg11, g11, logn);
//        memcpy(g11, tmp, n * sizeof *tmp);
        System.arraycopy(srctmp, tmp, srcg11, g11, n);
//        memcpy(tmp, g01, n * sizeof *g01);
        System.arraycopy(srcg01, g01, srctmp, tmp, n);
//        memcpy(g01, g00, hn * sizeof *g00);
        System.arraycopy(srcg00, g00, srcg01, g01, hn);
//        memcpy(g01 + hn, g11, hn * sizeof *g00);
        System.arraycopy(srcg11, g11, srcg01, g01 + hn, hn);

        /*
         * The half-size Gram matrices for the recursive LDL tree
         * building are now:
         *   - left sub-tree: g00, g00+hn, g01
         *   - right sub-tree: g11, g11+hn, g01+hn
         * l10 is in tmp[].
         */

        /*
         * We split t1 and use the first recursive call on the two
         * halves, using the right sub-tree. The result is merged
         * back into tmp + 2*n.
         */
        z1 = tmp + n;
        fft.poly_split_fft(srctmp, z1, srctmp, z1 + hn, srct1, t1, logn);
        ffSampling_fft_dyntree(samp, samp_ctx, srctmp, z1, srctmp, z1 + hn,
            srcg11, g11, srcg11, g11 + hn, srcg01, g01 + hn, orig_logn, logn - 1, srctmp, z1 + n);
        fft.poly_merge_fft(srctmp, tmp + (n << 1), srctmp, z1, srctmp, z1 + hn, logn);

        /*
         * Compute tb0 = t0 + (t1 - z1) * l10.
         * At that point, l10 is in tmp, t1 is unmodified, and z1 is
         * in tmp + (n << 1). The buffer in z1 is free.
         *
         * In the end, z1 is written over t1, and tb0 is in t0.
         */
//        memcpy(z1, t1, n * sizeof *t1);
        System.arraycopy(srct1, t1, srctmp, z1, n);
        fft.poly_sub(srctmp, z1, srctmp, tmp + (n << 1), logn);
//        memcpy(t1, tmp + (n << 1), n * sizeof *tmp);
        System.arraycopy(srctmp, tmp + (n << 1), srct1, t1, n);
        fft.poly_mul_fft(srctmp, tmp, srctmp, z1, logn);
        fft.poly_add(srct0, t0, srctmp, tmp, logn);

        /*
         * Second recursive invocation, on the split tb0 (currently in t0)
         * and the left sub-tree.
         */
        z0 = tmp;
        fft.poly_split_fft(srctmp, z0, srctmp, z0 + hn, srct0, t0, logn);
        ffSampling_fft_dyntree(samp, samp_ctx, srctmp, z0, srctmp, z0 + hn,
            srcg00, g00, srcg00, g00 + hn, srcg01, g01, orig_logn, logn - 1, srctmp, z0 + n);
        fft.poly_merge_fft(srct0, t0, srctmp, z0, srctmp, z0 + hn, logn);
    }

    /*
     * Perform Fast Fourier Sampling for target vector t and LDL tree T.
     * tmp[] must have size for at least two polynomials of size 2^logn.
     */
    void ffSampling_fft(SamplerZ samp, SamplerCtx samp_ctx,
                        FalconFPR[] srcz0, int z0, FalconFPR[] srcz1, int z1,
                        FalconFPR[] srctree, int tree,
                        FalconFPR[] srct0, int t0, FalconFPR[] srct1, int t1, int logn,
                        FalconFPR[] srctmp, int tmp)
    {
        int n, hn;
        int tree0, tree1;

        /*
         * When logn == 2, we inline the last two recursion levels.
         */
        if (logn == 2)
        {
            FalconFPR x0, x1, y0, y1, w0, w1, w2, w3, sigma;
            FalconFPR a_re, a_im, b_re, b_im, c_re, c_im;

            tree0 = tree + 4;
            tree1 = tree + 8;

            /*
             * We split t1 into w*, then do the recursive invocation,
             * with output in w*. We finally merge back into z1.
             */
            a_re = srct1[t1 + 0];
            a_im = srct1[t1 + 2];
            b_re = srct1[t1 + 1];
            b_im = srct1[t1 + 3];
            c_re = fpr.fpr_add(a_re, b_re);
            c_im = fpr.fpr_add(a_im, b_im);
            w0 = fpr.fpr_half(c_re);
            w1 = fpr.fpr_half(c_im);
            c_re = fpr.fpr_sub(a_re, b_re);
            c_im = fpr.fpr_sub(a_im, b_im);
            w2 = fpr.fpr_mul(fpr.fpr_add(c_re, c_im), fpr.fpr_invsqrt8);
            w3 = fpr.fpr_mul(fpr.fpr_sub(c_im, c_re), fpr.fpr_invsqrt8);

            x0 = w2;
            x1 = w3;
            sigma = srctree[tree1 + 3];
            w2 = fpr.fpr_of(samp.sample(samp_ctx, x0, sigma));
            w3 = fpr.fpr_of(samp.sample(samp_ctx, x1, sigma));
            a_re = fpr.fpr_sub(x0, w2);
            a_im = fpr.fpr_sub(x1, w3);
            b_re = srctree[tree1 + 0];
            b_im = srctree[tree1 + 1];
            c_re = fpr.fpr_sub(fpr.fpr_mul(a_re, b_re), fpr.fpr_mul(a_im, b_im));
            c_im = fpr.fpr_add(fpr.fpr_mul(a_re, b_im), fpr.fpr_mul(a_im, b_re));
            x0 = fpr.fpr_add(c_re, w0);
            x1 = fpr.fpr_add(c_im, w1);
            sigma = srctree[tree1 + 2];
            w0 = fpr.fpr_of(samp.sample(samp_ctx, x0, sigma));
            w1 = fpr.fpr_of(samp.sample(samp_ctx, x1, sigma));

            a_re = w0;
            a_im = w1;
            b_re = w2;
            b_im = w3;
            c_re = fpr.fpr_mul(fpr.fpr_sub(b_re, b_im), fpr.fpr_invsqrt2);
            c_im = fpr.fpr_mul(fpr.fpr_add(b_re, b_im), fpr.fpr_invsqrt2);
            srcz1[z1 + 0] = w0 = fpr.fpr_add(a_re, c_re);
            srcz1[z1 + 2] = w2 = fpr.fpr_add(a_im, c_im);
            srcz1[z1 + 1] = w1 = fpr.fpr_sub(a_re, c_re);
            srcz1[z1 + 3] = w3 = fpr.fpr_sub(a_im, c_im);

            /*
             * Compute tb0 = t0 + (t1 - z1) * L. Value tb0 ends up in w*.
             */
            w0 = fpr.fpr_sub(srct1[t1 + 0], w0);
            w1 = fpr.fpr_sub(srct1[t1 + 1], w1);
            w2 = fpr.fpr_sub(srct1[t1 + 2], w2);
            w3 = fpr.fpr_sub(srct1[t1 + 3], w3);

            a_re = w0;
            a_im = w2;
            b_re = srctree[tree + 0];
            b_im = srctree[tree + 2];
            w0 = fpr.fpr_sub(fpr.fpr_mul(a_re, b_re), fpr.fpr_mul(a_im, b_im));
            w2 = fpr.fpr_add(fpr.fpr_mul(a_re, b_im), fpr.fpr_mul(a_im, b_re));
            a_re = w1;
            a_im = w3;
            b_re = srctree[tree + 1];
            b_im = srctree[tree + 3];
            w1 = fpr.fpr_sub(fpr.fpr_mul(a_re, b_re), fpr.fpr_mul(a_im, b_im));
            w3 = fpr.fpr_add(fpr.fpr_mul(a_re, b_im), fpr.fpr_mul(a_im, b_re));

            w0 = fpr.fpr_add(w0, srct0[t0 + 0]);
            w1 = fpr.fpr_add(w1, srct0[t0 + 1]);
            w2 = fpr.fpr_add(w2, srct0[t0 + 2]);
            w3 = fpr.fpr_add(w3, srct0[t0 + 3]);

            /*
             * Second recursive invocation.
             */
            a_re = w0;
            a_im = w2;
            b_re = w1;
            b_im = w3;
            c_re = fpr.fpr_add(a_re, b_re);
            c_im = fpr.fpr_add(a_im, b_im);
            w0 = fpr.fpr_half(c_re);
            w1 = fpr.fpr_half(c_im);
            c_re = fpr.fpr_sub(a_re, b_re);
            c_im = fpr.fpr_sub(a_im, b_im);
            w2 = fpr.fpr_mul(fpr.fpr_add(c_re, c_im), fpr.fpr_invsqrt8);
            w3 = fpr.fpr_mul(fpr.fpr_sub(c_im, c_re), fpr.fpr_invsqrt8);

            x0 = w2;
            x1 = w3;
            sigma = srctree[tree0 + 3];
            w2 = y0 = fpr.fpr_of(samp.sample(samp_ctx, x0, sigma));
            w3 = y1 = fpr.fpr_of(samp.sample(samp_ctx, x1, sigma));
            a_re = fpr.fpr_sub(x0, y0);
            a_im = fpr.fpr_sub(x1, y1);
            b_re = srctree[tree0 + 0];
            b_im = srctree[tree0 + 1];
            c_re = fpr.fpr_sub(fpr.fpr_mul(a_re, b_re), fpr.fpr_mul(a_im, b_im));
            c_im = fpr.fpr_add(fpr.fpr_mul(a_re, b_im), fpr.fpr_mul(a_im, b_re));
            x0 = fpr.fpr_add(c_re, w0);
            x1 = fpr.fpr_add(c_im, w1);
            sigma = srctree[tree0 + 2];
            w0 = fpr.fpr_of(samp.sample(samp_ctx, x0, sigma));
            w1 = fpr.fpr_of(samp.sample(samp_ctx, x1, sigma));

            a_re = w0;
            a_im = w1;
            b_re = w2;
            b_im = w3;
            c_re = fpr.fpr_mul(fpr.fpr_sub(b_re, b_im), fpr.fpr_invsqrt2);
            c_im = fpr.fpr_mul(fpr.fpr_add(b_re, b_im), fpr.fpr_invsqrt2);
            srcz0[z0 + 0] = fpr.fpr_add(a_re, c_re);
            srcz0[z0 + 2] = fpr.fpr_add(a_im, c_im);
            srcz0[z0 + 1] = fpr.fpr_sub(a_re, c_re);
            srcz0[z0 + 3] = fpr.fpr_sub(a_im, c_im);

            return;
        }

        /*
         * Case logn == 1 is reachable only when using Falcon-2 (the
         * smallest size for which Falcon is mathematically defined, but
         * of course way too insecure to be of any use).
         */
        if (logn == 1)
        {
            FalconFPR x0, x1, y0, y1, sigma;
            FalconFPR a_re, a_im, b_re, b_im, c_re, c_im;

            x0 = srct1[t1 + 0];
            x1 = srct1[t1 + 1];
            sigma = srctree[tree + 3];
            srcz1[z1 + 0] = y0 = fpr.fpr_of(samp.sample(samp_ctx, x0, sigma));
            srcz1[z1 + 1] = y1 = fpr.fpr_of(samp.sample(samp_ctx, x1, sigma));
            a_re = fpr.fpr_sub(x0, y0);
            a_im = fpr.fpr_sub(x1, y1);
            b_re = srctree[tree + 0];
            b_im = srctree[tree + 1];
            c_re = fpr.fpr_sub(fpr.fpr_mul(a_re, b_re), fpr.fpr_mul(a_im, b_im));
            c_im = fpr.fpr_add(fpr.fpr_mul(a_re, b_im), fpr.fpr_mul(a_im, b_re));
            x0 = fpr.fpr_add(c_re, srct0[t0 + 0]);
            x1 = fpr.fpr_add(c_im, srct0[t0 + 1]);
            sigma = srctree[tree + 2];
            srcz0[z0 + 0] = fpr.fpr_of(samp.sample(samp_ctx, x0, sigma));
            srcz0[z0 + 1] = fpr.fpr_of(samp.sample(samp_ctx, x1, sigma));

            return;
        }

    /*
     * Normal end of recursion is for logn == 0. Since the last
     * steps of the recursions were inlined in the blocks above
     * (when logn == 1 or 2), this case is not reachable, and is
     * retained here only for documentation purposes.

    if (logn == 0) {
        fpr x0, x1, sigma;

        x0 = t0[0];
        x1 = t1[0];
        sigma = tree[0];
        z0[0] = fpr_of(samp(samp_ctx, x0, sigma));
        z1[0] = fpr_of(samp(samp_ctx, x1, sigma));
        return;
    }

     */

        /*
         * General recursive case (logn >= 3).
         */

        n = 1 << logn;
        hn = n >> 1;
        tree0 = tree + n;
        tree1 = tree + n + ffLDL_treesize(logn - 1);

        /*
         * We split t1 into z1 (reused as temporary storage), then do
         * the recursive invocation, with output in tmp. We finally
         * merge back into z1.
         */
        fft.poly_split_fft(srcz1, z1, srcz1, z1 + hn, srct1, t1, logn);
        ffSampling_fft(samp, samp_ctx, srctmp, tmp, srctmp, tmp + hn,
            srctree, tree1, srcz1, z1, srcz1, z1 + hn, logn - 1, srctmp, tmp + n);
        fft.poly_merge_fft(srcz1, z1, srctmp, tmp, srctmp, tmp + hn, logn);

        /*
         * Compute tb0 = t0 + (t1 - z1) * L. Value tb0 ends up in tmp[].
         */
//        memcpy(tmp, t1, n * sizeof *t1);
        System.arraycopy(srct1, t1, srctmp, tmp, n);
        fft.poly_sub(srctmp, tmp, srcz1, z1, logn);
        fft.poly_mul_fft(srctmp, tmp, srctree, tree, logn);
        fft.poly_add(srctmp, tmp, srct0, t0, logn);

        /*
         * Second recursive invocation.
         */
        fft.poly_split_fft(srcz0, z0, srcz0, z0 + hn, srctmp, tmp, logn);
        ffSampling_fft(samp, samp_ctx, srctmp, tmp, srctmp, tmp + hn,
            srctree, tree0, srcz0, z0, srcz0, z0 + hn, logn - 1, srctmp, tmp + n);
        fft.poly_merge_fft(srcz0, z0, srctmp, tmp, srctmp, tmp + hn, logn);
    }

    /*
     * Compute a signature: the signature contains two vectors, s1 and s2.
     * The s1 vector is not returned. The squared norm of (s1,s2) is
     * computed, and if it is short enough, then s2 is returned into the
     * s2[] buffer, and 1 is returned; otherwise, s2[] is untouched and 0 is
     * returned; the caller should then try again. This function uses an
     * expanded key.
     *
     * tmp[] must have room for at least six polynomials.
     */
    int do_sign_tree(SamplerZ samp, SamplerCtx samp_ctx, short[] srcs2, int s2,
                     FalconFPR[] srcexpanded_key, int expanded_key,
                     short[] srchm, int hm,
                     int logn, FalconFPR[] srctmp, int tmp)
    {
        int n, u;
        int t0, t1, tx, ty;
        int b00, b01, b10, b11, tree;
        FalconFPR ni;
        int sqn, ng;
        short[] s1tmp, s2tmp;

        n = MKN(logn);
        t0 = tmp;
        t1 = t0 + n;
        b00 = expanded_key + skoff_b00(logn);
        b01 = expanded_key + skoff_b01(logn);
        b10 = expanded_key + skoff_b10(logn);
        b11 = expanded_key + skoff_b11(logn);
        tree = expanded_key + skoff_tree(logn);

        /*
         * Set the target vector to [hm, 0] (hm is the hashed message).
         */
        for (u = 0; u < n; u++)
        {
            srctmp[t0 + u] = fpr.fpr_of(srchm[hm + u]);
        /* This is implicit.
        t1[u] = fpr_zero;
        */
        }

        /*
         * Apply the lattice basis to obtain the real target
         * vector (after normalization with regards to modulus).
         */
        fft.FFT(srctmp, t0, logn);
        ni = fpr.fpr_inverse_of_q;
//        memcpy(t1, t0, n * sizeof *t0);
        System.arraycopy(srctmp, t0, srctmp, t1, n);
        fft.poly_mul_fft(srctmp, t1, srcexpanded_key, b01, logn);
        fft.poly_mulconst(srctmp, t1, fpr.fpr_neg(ni), logn);
        fft.poly_mul_fft(srctmp, t0, srcexpanded_key, b11, logn);
        fft.poly_mulconst(srctmp, t0, ni, logn);

        tx = t1 + n;
        ty = tx + n;

        /*
         * Apply sampling. Output is written back in [tx, ty].
         */
        ffSampling_fft(samp, samp_ctx, srctmp, tx, srctmp, ty, srcexpanded_key, tree,
            srctmp, t0, srctmp, t1, logn, srctmp, ty + n);

        /*
         * Get the lattice point corresponding to that tiny vector.
         */
//        memcpy(t0, tx, n * sizeof *tx);
        System.arraycopy(srctmp, tx, srctmp, t0, n);
//        memcpy(t1, ty, n * sizeof *ty);
        System.arraycopy(srctmp, ty, srctmp, t1, n);
        fft.poly_mul_fft(srctmp, tx, srcexpanded_key, b00, logn);
        fft.poly_mul_fft(srctmp, ty, srcexpanded_key, b10, logn);
        fft.poly_add(srctmp, tx, srctmp, ty, logn);
//        memcpy(ty, t0, n * sizeof *t0);
        System.arraycopy(srctmp, t0, srctmp, ty, n);
        fft.poly_mul_fft(srctmp, ty, srcexpanded_key, b01, logn);

//        memcpy(t0, tx, n * sizeof *tx);
        System.arraycopy(srctmp, tx, srctmp, t0, n);
        fft.poly_mul_fft(srctmp, t1, srcexpanded_key, b11, logn);
        fft.poly_add(srctmp, t1, srctmp, ty, logn);

        fft.iFFT(srctmp, t0, logn);
        fft.iFFT(srctmp, t1, logn);

        /*
         * Compute the signature.
         */
        s1tmp = new short[n];
        sqn = 0;
        ng = 0;
        for (u = 0; u < n; u++)
        {
            int z;
            // note: hm is unsigned
            z = (srchm[hm + u] & 0xffff) - (int)fpr.fpr_rint(srctmp[t0 + u]);
            sqn += (z * z);
            ng |= sqn;
            s1tmp[u] = (short)z;
        }
        sqn |= -(ng >>> 31);

        /*
         * With "normal" degrees (e.g. 512 or 1024), it is very
         * improbable that the computed vector is not short enough;
         * however, it may happen in practice for the very reduced
         * versions (e.g. degree 16 or below). In that case, the caller
         * will loop, and we must not write anything into s2[] because
         * s2[] may overlap with the hashed message hm[] and we need
         * hm[] for the next iteration.
         */
        s2tmp = new short[n];
        for (u = 0; u < n; u++)
        {
            s2tmp[u] = (short)-fpr.fpr_rint(srctmp[t1 + u]);
        }
        if (common.is_short_half(sqn, s2tmp, 0, logn) != 0)
        {
//            memcpy(s2, s2tmp, n * sizeof *s2);
            System.arraycopy(s2tmp, 0, srcs2, s2, n);
//            memcpy(tmp, s1tmp, n * sizeof *s1tmp);
            System.arraycopy(s1tmp, 0, srctmp, tmp, n);
            return 1;
        }
        return 0;
    }

    /*
     * Compute a signature: the signature contains two vectors, s1 and s2.
     * The s1 vector is not returned. The squared norm of (s1,s2) is
     * computed, and if it is short enough, then s2 is returned into the
     * s2[] buffer, and 1 is returned; otherwise, s2[] is untouched and 0 is
     * returned; the caller should then try again.
     *
     * tmp[] must have room for at least nine polynomials.
     */
    int do_sign_dyn(SamplerZ samp, SamplerCtx samp_ctx, short[] srcs2, int s2,
                    byte[] srcf, int f, byte[] srcg, int g,
                    byte[] srcF, int F, byte[] srcG, int G,
                    short[] srchm, int hm, int logn, FalconFPR[] srctmp, int tmp)
    {
        int n, u;
        int t0, t1, tx, ty;
        int b00, b01, b10, b11, g00, g01, g11;
        FalconFPR ni;
        int sqn, ng;
        short[] s1tmp, s2tmp;

        n = MKN(logn);

        /*
         * Lattice basis is B = [[g, -f], [G, -F]]. We convert it to FFT.
         */
        b00 = tmp;
        b01 = b00 + n;
        b10 = b01 + n;
        b11 = b10 + n;
        smallints_to_fpr(srctmp, b01, srcf, f, logn);
        smallints_to_fpr(srctmp, b00, srcg, g, logn);
        smallints_to_fpr(srctmp, b11, srcF, F, logn);
        smallints_to_fpr(srctmp, b10, srcG, G, logn);
        fft.FFT(srctmp, b01, logn);
        fft.FFT(srctmp, b00, logn);
        fft.FFT(srctmp, b11, logn);
        fft.FFT(srctmp, b10, logn);
        fft.poly_neg(srctmp, b01, logn);
        fft.poly_neg(srctmp, b11, logn);

        /*
         * Compute the Gram matrix G = B·B*. Formulas are:
         *   g00 = b00*adj(b00) + b01*adj(b01)
         *   g01 = b00*adj(b10) + b01*adj(b11)
         *   g10 = b10*adj(b00) + b11*adj(b01)
         *   g11 = b10*adj(b10) + b11*adj(b11)
         *
         * For historical reasons, this implementation uses
         * g00, g01 and g11 (upper triangle). g10 is not kept
         * since it is equal to adj(g01).
         *
         * We _replace_ the matrix B with the Gram matrix, but we
         * must keep b01 and b11 for computing the target vector.
         */
        t0 = b11 + n;
        t1 = t0 + n;

//        memcpy(t0, b01, n * sizeof *b01);
        System.arraycopy(srctmp, b01, srctmp, t0, n);
        fft.poly_mulselfadj_fft(srctmp, t0, logn);    // t0 <- b01*adj(b01)

//        memcpy(t1, b00, n * sizeof *b00);
        System.arraycopy(srctmp, b00, srctmp, t1, n);
        fft.poly_muladj_fft(srctmp, t1, srctmp, b10, logn);   // t1 <- b00*adj(b10)
        fft.poly_mulselfadj_fft(srctmp, b00, logn);   // b00 <- b00*adj(b00)
        fft.poly_add(srctmp, b00, srctmp, t0, logn);      // b00 <- g00
//        memcpy(t0, b01, n * sizeof *b01);
        System.arraycopy(srctmp, b01, srctmp, t0, n);
        fft.poly_muladj_fft(srctmp, b01, srctmp, b11, logn);  // b01 <- b01*adj(b11)
        fft.poly_add(srctmp, b01, srctmp, t1, logn);      // b01 <- g01

        fft.poly_mulselfadj_fft(srctmp, b10, logn);   // b10 <- b10*adj(b10)
//        memcpy(t1, b11, n * sizeof *b11);
        System.arraycopy(srctmp, b11, srctmp, t1, n);
        fft.poly_mulselfadj_fft(srctmp, t1, logn);    // t1 <- b11*adj(b11)
        fft.poly_add(srctmp, b10, srctmp, t1, logn);      // b10 <- g11

        /*
         * We rename variables to make things clearer. The three elements
         * of the Gram matrix uses the first 3*n slots of tmp[], followed
         * by b11 and b01 (in that order).
         */
        g00 = b00;
        g01 = b01;
        g11 = b10;
        b01 = t0;
        t0 = b01 + n;
        t1 = t0 + n;

        /*
         * Memory layout at that point:
         *   g00 g01 g11 b11 b01 t0 t1
         */

        /*
         * Set the target vector to [hm, 0] (hm is the hashed message).
         */
        for (u = 0; u < n; u++)
        {
            srctmp[t0 + u] = fpr.fpr_of(srchm[hm + u]);
        /* This is implicit.
        t1[u] = fpr_zero;
        */
        }

        /*
         * Apply the lattice basis to obtain the real target
         * vector (after normalization with regards to modulus).
         */
        fft.FFT(srctmp, t0, logn);
        ni = fpr.fpr_inverse_of_q;
//        memcpy(t1, t0, n * sizeof *t0);
        System.arraycopy(srctmp, t0, srctmp, t1, n);
        fft.poly_mul_fft(srctmp, t1, srctmp, b01, logn);
        fft.poly_mulconst(srctmp, t1, fpr.fpr_neg(ni), logn);
        fft.poly_mul_fft(srctmp, t0, srctmp, b11, logn);
        fft.poly_mulconst(srctmp, t0, ni, logn);

        /*
         * b01 and b11 can be discarded, so we move back (t0,t1).
         * Memory layout is now:
         *      g00 g01 g11 t0 t1
         */
//        memcpy(b11, t0, n * 2 * sizeof *t0);
        System.arraycopy(srctmp, t0, srctmp, b11, 2 * n);
        t0 = g11 + n;
        t1 = t0 + n;

        /*
         * Apply sampling; result is written over (t0,t1).
         */
        ffSampling_fft_dyntree(samp, samp_ctx,
            srctmp, t0, srctmp, t1,
            srctmp, g00, srctmp, g01, srctmp, g11,
            logn, logn, srctmp, t1 + n);

        /*
         * We arrange the layout back to:
         *     b00 b01 b10 b11 t0 t1
         *
         * We did not conserve the matrix basis, so we must recompute
         * it now.
         */
        b00 = tmp;
        b01 = b00 + n;
        b10 = b01 + n;
        b11 = b10 + n;
//        memmove(b11 + n, t0, n * 2 * sizeof *t0);
        System.arraycopy(srctmp, t0, srctmp, b11 + n, n * 2);
        t0 = b11 + n;
        t1 = t0 + n;
        smallints_to_fpr(srctmp, b01, srcf, f, logn);
        smallints_to_fpr(srctmp, b00, srcg, g, logn);
        smallints_to_fpr(srctmp, b11, srcF, F, logn);
        smallints_to_fpr(srctmp, b10, srcG, G, logn);
        fft.FFT(srctmp, b01, logn);
        fft.FFT(srctmp, b00, logn);
        fft.FFT(srctmp, b11, logn);
        fft.FFT(srctmp, b10, logn);
        fft.poly_neg(srctmp, b01, logn);
        fft.poly_neg(srctmp, b11, logn);
        tx = t1 + n;
        ty = tx + n;

        /*
         * Get the lattice point corresponding to that tiny vector.
         */
//        memcpy(tx, t0, n * sizeof *t0);
        System.arraycopy(srctmp, t0, srctmp, tx, n);
//        memcpy(ty, t1, n * sizeof *t1);
        System.arraycopy(srctmp, t1, srctmp, ty, n);
        fft.poly_mul_fft(srctmp, tx, srctmp, b00, logn);
        fft.poly_mul_fft(srctmp, ty, srctmp, b10, logn);
        fft.poly_add(srctmp, tx, srctmp, ty, logn);
//        memcpy(ty, t0, n * sizeof *t0);
        System.arraycopy(srctmp, t0, srctmp, ty, n);
        fft.poly_mul_fft(srctmp, ty, srctmp, b01, logn);

//        memcpy(t0, tx, n * sizeof *tx);
        System.arraycopy(srctmp, tx, srctmp, t0, n);
        fft.poly_mul_fft(srctmp, t1, srctmp, b11, logn);
        fft.poly_add(srctmp, t1, srctmp, ty, logn);
        fft.iFFT(srctmp, t0, logn);
        fft.iFFT(srctmp, t1, logn);

        s1tmp = new short[n];
        sqn = 0;
        ng = 0;
        for (u = 0; u < n; u++)
        {
            int z;

            z = (srchm[hm + u] & 0xffff) - (int)fpr.fpr_rint(srctmp[t0 + u]);
            sqn += (z * z);
            ng |= sqn;
            s1tmp[u] = (short)z;
        }
        sqn |= -(ng >>> 31);

        /*
         * With "normal" degrees (e.g. 512 or 1024), it is very
         * improbable that the computed vector is not short enough;
         * however, it may happen in practice for the very reduced
         * versions (e.g. degree 16 or below). In that case, the caller
         * will loop, and we must not write anything into s2[] because
         * s2[] may overlap with the hashed message hm[] and we need
         * hm[] for the next iteration.
         */
        s2tmp = new short[n];
        for (u = 0; u < n; u++)
        {
            s2tmp[u] = (short)-fpr.fpr_rint(srctmp[t1 + u]);
        }
        if (common.is_short_half(sqn, s2tmp, 0, logn) != 0)
        {
//        memcpy(s2, s2tmp, n * sizeof *s2);
            System.arraycopy(s2tmp, 0, srcs2, s2, n);
//        memcpy(tmp, s1tmp, n * sizeof *s1tmp);
//            System.arraycopy(s1tmp, 0, srctmp, tmp, n);
            return 1;
        }
        return 0;
    }


    /* see inner.h */
    void sign_tree(short[] srcsig, int sig, SHAKE256 rng,
                   FalconFPR[] srcexpanded_key, int expanded_key,
                   short[] srchm, int hm, int logn, FalconFPR[] srctmp, int tmp)
    {
        int ftmp;

        ftmp = tmp;
        for (; ; )
        {
            /*
             * Signature produces short vectors s1 and s2. The
             * signature is acceptable only if the aggregate vector
             * s1,s2 is short; we must use the same bound as the
             * verifier.
             *
             * If the signature is acceptable, then we return only s2
             * (the verifier recomputes s1 from s2, the hashed message,
             * and the public key).
             */
            SamplerCtx spc = new SamplerCtx();
            SamplerZ samp = new SamplerZ();
            SamplerCtx samp_ctx;

            /*
             * Normal sampling. We use a fast PRNG seeded from our
             * SHAKE context ('rng').
             */
            spc.sigma_min = fpr.fpr_sigma_min[logn];
            spc.p.prng_init(rng);
            samp_ctx = spc;

            /*
             * Do the actual signature.
             */
            if (do_sign_tree(samp, samp_ctx, srcsig, sig,
                srcexpanded_key, expanded_key, srchm, hm, logn, srctmp, ftmp) != 0)
            {
                break;
            }
        }
    }

    /* see inner.h */
    void sign_dyn(short[] srcsig, int sig, SHAKE256 rng,
                  byte[] srcf, int f, byte[] srcg, int g,
                  byte[] srcF, int F, byte[] srcG, int G,
                  short[] srchm, int hm, int logn, FalconFPR[] srctmp, int tmp)
    {
        int ftmp;

        ftmp = tmp;
        for (; ; )
        {
            /*
             * Signature produces short vectors s1 and s2. The
             * signature is acceptable only if the aggregate vector
             * s1,s2 is short; we must use the same bound as the
             * verifier.
             *
             * If the signature is acceptable, then we return only s2
             * (the verifier recomputes s1 from s2, the hashed message,
             * and the public key).
             */
            SamplerCtx spc = new SamplerCtx();
            SamplerZ samp = new SamplerZ();
            SamplerCtx samp_ctx;

            /*
             * Normal sampling. We use a fast PRNG seeded from our
             * SHAKE context ('rng').
             */
            spc.sigma_min = fpr.fpr_sigma_min[logn];
            spc.p.prng_init(rng);
            samp_ctx = spc;

            /*
             * Do the actual signature.
             */
            if (do_sign_dyn(samp, samp_ctx, srcsig, sig,
                srcf, f, srcg, g, srcF, F, srcG, G, srchm, hm, logn, srctmp, ftmp) != 0)
            {
                break;
            }
        }
    }
}
