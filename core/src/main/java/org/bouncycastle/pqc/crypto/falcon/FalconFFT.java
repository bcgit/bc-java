package org.bouncycastle.pqc.crypto.falcon;

class FalconFFT
{
    FPREngine fpr;

    FalconFFT()
    {
        fpr = new FPREngine();
    }

    // complex number functions
    ComplexNumberWrapper FPC_ADD(FalconFPR a_re, FalconFPR a_im, FalconFPR b_re, FalconFPR b_im)
    {
        FalconFPR fpct_re, fpct_im;
        fpct_re = fpr.fpr_add(a_re, b_re);
        fpct_im = fpr.fpr_add(a_im, b_im);
        return new ComplexNumberWrapper(fpct_re, fpct_im);
    }

    ComplexNumberWrapper FPC_SUB(FalconFPR a_re, FalconFPR a_im, FalconFPR b_re, FalconFPR b_im)
    {
        FalconFPR fpct_re, fpct_im;
        fpct_re = fpr.fpr_sub(a_re, b_re);
        fpct_im = fpr.fpr_sub(a_im, b_im);
        return new ComplexNumberWrapper(fpct_re, fpct_im);
    }

    ComplexNumberWrapper FPC_MUL(FalconFPR a_re, FalconFPR a_im, FalconFPR b_re, FalconFPR b_im)
    {
        FalconFPR fpct_a_re, fpct_a_im;
        FalconFPR fpct_b_re, fpct_b_im;
        FalconFPR fpct_d_re, fpct_d_im;
        fpct_a_re = (a_re);
        fpct_a_im = (a_im);
        fpct_b_re = (b_re);
        fpct_b_im = (b_im);
        fpct_d_re = fpr.fpr_sub(
            fpr.fpr_mul(fpct_a_re, fpct_b_re),
            fpr.fpr_mul(fpct_a_im, fpct_b_im));
        fpct_d_im = fpr.fpr_add(
            fpr.fpr_mul(fpct_a_re, fpct_b_im),
            fpr.fpr_mul(fpct_a_im, fpct_b_re));
        return new ComplexNumberWrapper(fpct_d_re, fpct_d_im);
    }

    ComplexNumberWrapper FPC_SQR(FalconFPR a_re, FalconFPR a_im)
    {
        FalconFPR fpct_a_re, fpct_a_im;
        FalconFPR fpct_d_re, fpct_d_im;
        fpct_a_re = (a_re);
        fpct_a_im = (a_im);
        fpct_d_re = fpr.fpr_sub(fpr.fpr_sqr(fpct_a_re), fpr.fpr_sqr(fpct_a_im));
        fpct_d_im = fpr.fpr_double(fpr.fpr_mul(fpct_a_re, fpct_a_im));
        return new ComplexNumberWrapper(fpct_d_re, fpct_d_im);
    }

    ComplexNumberWrapper FPC_INV(FalconFPR a_re, FalconFPR a_im)
    {
        FalconFPR fpct_a_re, fpct_a_im;
        FalconFPR fpct_d_re, fpct_d_im;
        FalconFPR fpct_m;
        fpct_a_re = (a_re);
        fpct_a_im = (a_im);
        fpct_m = fpr.fpr_add(fpr.fpr_sqr(fpct_a_re), fpr.fpr_sqr(fpct_a_im));
        fpct_m = fpr.fpr_inv(fpct_m);
        fpct_d_re = fpr.fpr_mul(fpct_a_re, fpct_m);
        fpct_d_im = fpr.fpr_mul(fpr.fpr_neg(fpct_a_im), fpct_m);
        return new ComplexNumberWrapper(fpct_d_re, fpct_d_im);
    }

    ComplexNumberWrapper FPC_DIV(FalconFPR a_re, FalconFPR a_im, FalconFPR b_re, FalconFPR b_im)
    {
        FalconFPR fpct_a_re, fpct_a_im;
        FalconFPR fpct_b_re, fpct_b_im;
        FalconFPR fpct_d_re, fpct_d_im;
        FalconFPR fpct_m;
        fpct_a_re = (a_re);
        fpct_a_im = (a_im);
        fpct_b_re = (b_re);
        fpct_b_im = (b_im);
        fpct_m = fpr.fpr_add(fpr.fpr_sqr(fpct_b_re), fpr.fpr_sqr(fpct_b_im));
        fpct_m = fpr.fpr_inv(fpct_m);
        fpct_b_re = fpr.fpr_mul(fpct_b_re, fpct_m);
        fpct_b_im = fpr.fpr_mul(fpr.fpr_neg(fpct_b_im), fpct_m);
        fpct_d_re = fpr.fpr_sub(
            fpr.fpr_mul(fpct_a_re, fpct_b_re),
            fpr.fpr_mul(fpct_a_im, fpct_b_im));
        fpct_d_im = fpr.fpr_add(
            fpr.fpr_mul(fpct_a_re, fpct_b_im),
            fpr.fpr_mul(fpct_a_im, fpct_b_re));
        return new ComplexNumberWrapper(fpct_d_re, fpct_d_im);
    }

    /*
     * Let w = exp(i*pi/N); w is a primitive 2N-th root of 1. We define the
     * values w_j = w^(2j+1) for all j from 0 to N-1: these are the roots
     * of X^N+1 in the field of complex numbers. A crucial property is that
     * w_{N-1-j} = conj(w_j) = 1/w_j for all j.
     *
     * FFT representation of a polynomial f (taken modulo X^N+1) is the
     * set of values f(w_j). Since f is real, conj(f(w_j)) = f(conj(w_j)),
     * thus f(w_{N-1-j}) = conj(f(w_j)). We thus store only half the values,
     * for j = 0 to N/2-1; the other half can be recomputed easily when (if)
     * needed. A consequence is that FFT representation has the same size
     * as normal representation: N/2 complex numbers use N real numbers (each
     * complex number is the combination of a real and an imaginary part).
     *
     * We use a specific ordering which makes computations easier. Let rev()
     * be the bit-reversal function over log(N) bits. For j in 0..N/2-1, we
     * store the real and imaginary parts of f(w_j) in slots:
     *
     *    Re(f(w_j)) -> slot rev(j)/2
     *    Im(f(w_j)) -> slot rev(j)/2+N/2
     *
     * (Note that rev(j) is even for j < N/2.)
     */

    /* see inner.h */
    void FFT(FalconFPR[] srcf, int f, int logn)
    {
        /*
         * FFT algorithm in bit-reversal order uses the following
         * iterative algorithm:
         *
         *   t = N
         *   for m = 1; m < N; m *= 2:
         *       ht = t/2
         *       for i1 = 0; i1 < m; i1 ++:
         *           j1 = i1 * t
         *           s = GM[m + i1]
         *           for j = j1; j < (j1 + ht); j ++:
         *               x = f[j]
         *               y = s * f[j + ht]
         *               f[j] = x + y
         *               f[j + ht] = x - y
         *       t = ht
         *
         * GM[k] contains w^rev(k) for primitive root w = exp(i*pi/N).
         *
         * In the description above, f[] is supposed to contain complex
         * numbers. In our in-memory representation, the real and
         * imaginary parts of f[k] are in array slots k and k+N/2.
         *
         * We only keep the first half of the complex numbers. We can
         * see that after the first iteration, the first and second halves
         * of the array of complex numbers have separate lives, so we
         * simply ignore the second part.
         */

        int u;
        int t, n, hn, m;

        /*
         * First iteration: compute f[j] + i * f[j+N/2] for all j < N/2
         * (because GM[1] = w^rev(1) = w^(N/2) = i).
         * In our chosen representation, this is a no-op: everything is
         * already where it should be.
         */

        /*
         * Subsequent iterations are truncated to use only the first
         * half of values.
         */
        n = 1 << logn;
        hn = n >> 1;
        t = hn;
        for (u = 1, m = 2; u < logn; u++, m <<= 1)
        {
            int ht, hm, i1, j1;

            ht = t >> 1;
            hm = m >> 1;
            for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t)
            {
                int j, j2;

                j2 = j1 + ht;
                FalconFPR s_re, s_im;

                s_re = fpr.fpr_gm_tab[((m + i1) << 1) + 0];
                s_im = fpr.fpr_gm_tab[((m + i1) << 1) + 1];
                for (j = j1; j < j2; j++)
                {
                    FalconFPR x_re, x_im, y_re, y_im;
                    ComplexNumberWrapper res;

                    x_re = srcf[f + j];
                    x_im = srcf[f + j + hn];
                    y_re = srcf[f + j + ht];
                    y_im = srcf[f + j + ht + hn];
                    res = FPC_MUL(y_re, y_im, s_re, s_im);
                    y_re = res.re;
                    y_im = res.im;

                    res = FPC_ADD(x_re, x_im, y_re, y_im);
                    srcf[f + j] = res.re;
                    srcf[f + j + hn] = res.im;

                    res = FPC_SUB(x_re, x_im, y_re, y_im);
                    srcf[f + j + ht] = res.re;
                    srcf[f + j + ht + hn] = res.im;
                }
            }
            t = ht;
        }
    }

    /* see inner.h */
    void iFFT(FalconFPR[] srcf, int f, int logn)
    {
        /*
         * Inverse FFT algorithm in bit-reversal order uses the following
         * iterative algorithm:
         *
         *   t = 1
         *   for m = N; m > 1; m /= 2:
         *       hm = m/2
         *       dt = t*2
         *       for i1 = 0; i1 < hm; i1 ++:
         *           j1 = i1 * dt
         *           s = iGM[hm + i1]
         *           for j = j1; j < (j1 + t); j ++:
         *               x = f[j]
         *               y = f[j + t]
         *               f[j] = x + y
         *               f[j + t] = s * (x - y)
         *       t = dt
         *   for i1 = 0; i1 < N; i1 ++:
         *       f[i1] = f[i1] / N
         *
         * iGM[k] contains (1/w)^rev(k) for primitive root w = exp(i*pi/N)
         * (actually, iGM[k] = 1/GM[k] = conj(GM[k])).
         *
         * In the main loop (not counting the final division loop), in
         * all iterations except the last, the first and second half of f[]
         * (as an array of complex numbers) are separate. In our chosen
         * representation, we do not keep the second half.
         *
         * The last iteration recombines the recomputed half with the
         * implicit half, and should yield only real numbers since the
         * target polynomial is real; moreover, s = i at that step.
         * Thus, when considering x and y:
         *    y = conj(x) since the final f[j] must be real
         *    Therefore, f[j] is filled with 2*Re(x), and f[j + t] is
         *    filled with 2*Im(x).
         * But we already have Re(x) and Im(x) in array slots j and j+t
         * in our chosen representation. That last iteration is thus a
         * simple doubling of the values in all the array.
         *
         * We make the last iteration a no-op by tweaking the final
         * division into a division by N/2, not N.
         */
        int u, n, hn, t, m;

        n = 1 << logn;
        t = 1;
        m = n;
        hn = n >> 1;
        for (u = logn; u > 1; u--)
        {
            int hm, dt, i1, j1;

            hm = m >> 1;
            dt = t << 1;
            for (i1 = 0, j1 = 0; j1 < hn; i1++, j1 += dt)
            {
                int j, j2;

                j2 = j1 + t;
                FalconFPR s_re, s_im;

                s_re = fpr.fpr_gm_tab[((hm + i1) << 1) + 0];
                s_im = fpr.fpr_neg(fpr.fpr_gm_tab[((hm + i1) << 1) + 1]);
                for (j = j1; j < j2; j++)
                {
                    FalconFPR x_re, x_im, y_re, y_im;
                    ComplexNumberWrapper res;

                    x_re = srcf[f + j];
                    x_im = srcf[f + j + hn];
                    y_re = srcf[f + j + t];
                    y_im = srcf[f + j + t + hn];
                    res = FPC_ADD(x_re, x_im, y_re, y_im);
                    srcf[f + j] = res.re;
                    srcf[f + j + hn] = res.im;

                    res = FPC_SUB(x_re, x_im, y_re, y_im);
                    x_re = res.re;
                    x_im = res.im;

                    res = FPC_MUL(x_re, x_im, s_re, s_im);
                    srcf[f + j + t] = res.re;
                    srcf[f + j + t + hn] = res.im;
                }
            }
            t = dt;
            m = hm;
        }

        /*
         * Last iteration is a no-op, provided that we divide by N/2
         * instead of N. We need to make a special case for logn = 0.
         */
        if (logn > 0)
        {
            FalconFPR ni;

            ni = fpr.fpr_p2_tab[logn];
            for (u = 0; u < n; u++)
            {
                srcf[f + u] = fpr.fpr_mul(srcf[f + u], ni);
            }
        }
    }

    /* see inner.h */
    void poly_add(
        FalconFPR[] srca, int a, FalconFPR[] srcb, int b, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            srca[a + u] = fpr.fpr_add(srca[a + u], srcb[b + u]);
        }
    }

    /* see inner.h */
    void poly_sub(
        FalconFPR[] srca, int a, FalconFPR[] srcb, int b, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            srca[a + u] = fpr.fpr_sub(srca[a + u], srcb[b + u]);
        }
    }

    /* see inner.h */
    void poly_neg(FalconFPR[] srca, int a, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            srca[a + u] = fpr.fpr_neg(srca[a + u]);
        }
    }

    /* see inner.h */
    void poly_adj_fft(FalconFPR[] srca, int a, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = (n >> 1); u < n; u++)
        {
            srca[a + u] = fpr.fpr_neg(srca[a + u]);
        }
    }

    /* see inner.h */
    void poly_mul_fft(
        FalconFPR[] srca, int a, FalconFPR[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            ComplexNumberWrapper res;

            a_re = srca[a + u];
            a_im = srca[a + u + hn];
            b_re = srcb[b + u];
            b_im = srcb[b + u + hn];
            res = FPC_MUL(a_re, a_im, b_re, b_im);
            srca[a + u] = res.re;
            srca[a + u + hn] = res.im;
        }
    }

    /* see inner.h */
    void poly_muladj_fft(
        FalconFPR[] srca, int a, FalconFPR[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            ComplexNumberWrapper res;

            a_re = srca[a + u];
            a_im = srca[a + u + hn];
            b_re = srcb[b + u];
            b_im = fpr.fpr_neg(srcb[b + u + hn]);
            res = FPC_MUL(a_re, a_im, b_re, b_im);
            srca[a + u] = res.re;
            srca[a + u + hn] = res.im;
        }
    }

    /* see inner.h */
    void poly_mulselfadj_fft(FalconFPR[] srca, int a, int logn)
    {
        /*
         * Since each coefficient is multiplied with its own conjugate,
         * the result contains only real values.
         */
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im;
            ComplexNumberWrapper res;

            a_re = srca[a + u];
            a_im = srca[a + u + hn];
            srca[a + u] = fpr.fpr_add(fpr.fpr_sqr(a_re), fpr.fpr_sqr(a_im));
            srca[a + u + hn] = fpr.fpr_zero;
        }
    }

    /* see inner.h */
    void poly_mulconst(FalconFPR[] srca, int a, FalconFPR x, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            srca[a + u] = fpr.fpr_mul(srca[a + u], x);
        }
    }

    /* see inner.h */
    void poly_div_fft(
        FalconFPR[] srca, int a, FalconFPR[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            ComplexNumberWrapper res;

            a_re = srca[a + u];
            a_im = srca[a + u + hn];
            b_re = srcb[b + u];
            b_im = srcb[b + u + hn];
            res = FPC_DIV(a_re, a_im, b_re, b_im);
            srca[a + u] = res.re;
            srca[a + u + hn] = res.im;
        }
    }

    /* see inner.h */
    void poly_invnorm2_fft(FalconFPR[] srcd, int d,
                           FalconFPR[] srca, int a, FalconFPR[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im;
            FalconFPR b_re, b_im;

            a_re = srca[a + u];
            a_im = srca[a + u + hn];
            b_re = srcb[b + u];
            b_im = srcb[b + u + hn];
            srcd[d + u] = fpr.fpr_inv(fpr.fpr_add(
                fpr.fpr_add(fpr.fpr_sqr(a_re), fpr.fpr_sqr(a_im)),
                fpr.fpr_add(fpr.fpr_sqr(b_re), fpr.fpr_sqr(b_im))));
        }
    }

    /* see inner.h */
    void poly_add_muladj_fft(FalconFPR[] srcd, int d,
                             FalconFPR[] srcF, int F, FalconFPR[] srcG, int G,
                             FalconFPR[] srcf, int f, FalconFPR[] srcg, int g, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR F_re, F_im, G_re, G_im;
            FalconFPR f_re, f_im, g_re, g_im;
            FalconFPR a_re, a_im, b_re, b_im;
            ComplexNumberWrapper res;

            F_re = srcF[F + u];
            F_im = srcF[F + u + hn];
            G_re = srcG[G + u];
            G_im = srcG[G + u + hn];
            f_re = srcf[f + u];
            f_im = srcf[f + u + hn];
            g_re = srcg[g + u];
            g_im = srcg[g + u + hn];

            res = FPC_MUL(F_re, F_im, f_re, fpr.fpr_neg(f_im));
            a_re = res.re;
            a_im = res.im;
            res = FPC_MUL(G_re, G_im, g_re, fpr.fpr_neg(g_im));
            b_re = res.re;
            b_im = res.im;
            srcd[d + u] = fpr.fpr_add(a_re, b_re);
            srcd[d + u + hn] = fpr.fpr_add(a_im, b_im);
        }
    }

    /* see inner.h */
    void poly_mul_autoadj_fft(
        FalconFPR[] srca, int a, FalconFPR[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            srca[a + u] = fpr.fpr_mul(srca[a + u], srcb[b + u]);
            srca[a + u + hn] = fpr.fpr_mul(srca[a + u + hn], srcb[b + u]);
        }
    }

    /* see inner.h */
    void poly_div_autoadj_fft(
        FalconFPR[] srca, int a, FalconFPR[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR ib;

            ib = fpr.fpr_inv(srcb[b + u]);
            srca[a + u] = fpr.fpr_mul(srca[a + u], ib);
            srca[a + u + hn] = fpr.fpr_mul(srca[a + u + hn], ib);
        }
    }

    /* see inner.h */
    void poly_LDL_fft(
        FalconFPR[] srcg00, int g00,
        FalconFPR[] srcg01, int g01, FalconFPR[] srcg11, int g11, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
            FalconFPR mu_re, mu_im;
            ComplexNumberWrapper res;

            g00_re = srcg00[g00 + u];
            g00_im = srcg00[g00 + u + hn];
            g01_re = srcg01[g01 + u];
            g01_im = srcg01[g01 + u + hn];
            g11_re = srcg11[g11 + u];
            g11_im = srcg11[g11 + u + hn];
            res = FPC_DIV(g01_re, g01_im, g00_re, g00_im);
            mu_re = res.re;
            mu_im = res.im;
            res = FPC_MUL(mu_re, mu_im, g01_re, fpr.fpr_neg(g01_im));
            g01_re = res.re;
            g01_im = res.im;
            res = FPC_SUB(g11_re, g11_im, g01_re, g01_im);
            srcg11[g11 + u] = res.re;
            srcg11[g11 + u + hn] = res.im;
            srcg01[g01 + u] = mu_re;
            srcg01[g01 + u + hn] = fpr.fpr_neg(mu_im);
        }
    }

    /* see inner.h */
    void poly_LDLmv_fft(
        FalconFPR[] srcd11, int d11, FalconFPR[] srcl10, int l10,
        FalconFPR[] srcg00, int g00, FalconFPR[] srcg01, int g01,
        FalconFPR[] srcg11, int g11, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
            FalconFPR mu_re, mu_im;
            ComplexNumberWrapper res;

            g00_re = srcg00[g00 + u];
            g00_im = srcg00[g00 + u + hn];
            g01_re = srcg01[g01 + u];
            g01_im = srcg01[g01 + u + hn];
            g11_re = srcg11[g11 + u];
            g11_im = srcg11[g11 + u + hn];
            res = FPC_DIV(g01_re, g01_im, g00_re, g00_im);
            mu_re = res.re;
            mu_im = res.im;
            res = FPC_MUL(mu_re, mu_im, g01_re, fpr.fpr_neg(g01_im));
            g01_re = res.re;
            g01_im = res.im;
            res = FPC_SUB(g11_re, g11_im, g01_re, g01_im);
            srcd11[d11 + u] = res.re;
            srcd11[d11 + u + hn] = res.im;
            srcl10[l10 + u] = mu_re;
            srcl10[l10 + u + hn] = fpr.fpr_neg(mu_im);
        }
    }

    /* see inner.h */
    void poly_split_fft(
        FalconFPR[] srcf0, int f0, FalconFPR[] srcf1, int f1,
        FalconFPR[] srcf, int f, int logn)
    {
        /*
         * The FFT representation we use is in bit-reversed order
         * (element i contains f(w^(rev(i))), where rev() is the
         * bit-reversal function over the ring degree. This changes
         * indexes with regards to the Falcon specification.
         */
        int n, hn, qn, u;

        n = 1 << logn;
        hn = n >> 1;
        qn = hn >> 1;

        /*
         * We process complex values by pairs. For logn = 1, there is only
         * one complex value (the other one is the implicit conjugate),
         * so we add the two lines below because the loop will be
         * skipped.
         */
        srcf0[f0 + 0] = srcf[f + 0];
        srcf1[f1 + 0] = srcf[f + hn];

        for (u = 0; u < qn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            FalconFPR t_re, t_im;
            ComplexNumberWrapper res;

            a_re = srcf[f + (u << 1) + 0];
            a_im = srcf[f + (u << 1) + 0 + hn];
            b_re = srcf[f + (u << 1) + 1];
            b_im = srcf[f + (u << 1) + 1 + hn];

            res = FPC_ADD(a_re, a_im, b_re, b_im);
            t_re = res.re;
            t_im = res.im;
            srcf0[f0 + u] = fpr.fpr_half(t_re);
            srcf0[f0 + u + qn] = fpr.fpr_half(t_im);

            res = FPC_SUB(a_re, a_im, b_re, b_im);
            t_re = res.re;
            t_im = res.im;
            res = FPC_MUL(t_re, t_im,
                fpr.fpr_gm_tab[((u + hn) << 1) + 0],
                fpr.fpr_neg(fpr.fpr_gm_tab[((u + hn) << 1) + 1]));
            t_re = res.re;
            t_im = res.im;
            srcf1[f1 + u] = fpr.fpr_half(t_re);
            srcf1[f1 + u + qn] = fpr.fpr_half(t_im);
        }
    }

    /* see inner.h */
    void poly_merge_fft(
        FalconFPR[] srcf, int f,
        FalconFPR[] srcf0, int f0, FalconFPR[] srcf1, int f1, int logn)
    {
        int n, hn, qn, u;

        n = 1 << logn;
        hn = n >> 1;
        qn = hn >> 1;

        /*
         * An extra copy to handle the special case logn = 1.
         */
        srcf[f + 0] = srcf0[f0 + 0];
        srcf[f + hn] = srcf1[f1 + 0];

        for (u = 0; u < qn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            FalconFPR t_re, t_im;
            ComplexNumberWrapper res;

            a_re = srcf0[f0 + u];
            a_im = srcf0[f0 + u + qn];
            res = FPC_MUL(srcf1[f1 + u], srcf1[f1 + u + qn],
                fpr.fpr_gm_tab[((u + hn) << 1) + 0],
                fpr.fpr_gm_tab[((u + hn) << 1) + 1]);
            b_re = res.re;
            b_im = res.im;
            res = FPC_ADD(a_re, a_im, b_re, b_im);
            t_re = res.re;
            t_im = res.im;
            srcf[f + (u << 1) + 0] = t_re;
            srcf[f + (u << 1) + 0 + hn] = t_im;
            res = FPC_SUB(a_re, a_im, b_re, b_im);
            t_re = res.re;
            t_im = res.im;
            srcf[f + (u << 1) + 1] = t_re;
            srcf[f + (u << 1) + 1 + hn] = t_im;
        }
    }

}
