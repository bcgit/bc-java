package org.bouncycastle.pqc.crypto.falcon;

class FalconFFT
{
//    FalconFFT()
//    {
//    }

    // complex number functions
//    static ComplexNumberWrapper FPC_ADD(double a_re, double a_im, double b_re, double b_im)
//    {
//        return new ComplexNumberWrapper(a_re + b_re, a_im + b_im);
//    }
//
//    static ComplexNumberWrapper FPC_SUB(double a_re, double a_im, double b_re, double b_im)
//    {
//        return new ComplexNumberWrapper(a_re - b_re, a_im - b_im);
//    }

//    static ComplexNumberWrapper FPC_MUL(double a_re, double a_im, double b_re, double b_im)
//    {
//        return new ComplexNumberWrapper(a_re * b_re - a_im * b_im, a_re * b_im + a_im * b_re);
//    }

//    ComplexNumberWrapper FPC_SQR(double a_re, double a_im)
//    {
//        double fpct_a_re, fpct_a_im;
//        double fpct_d_re, fpct_d_im;
//        fpct_a_re = (a_re);
//        fpct_a_im = (a_im);
//        fpct_d_re = FPREngine.fpr_sub(FPREngine.fpr_sqr(fpct_a_re), FPREngine.fpr_sqr(fpct_a_im));
//        fpct_d_im = FPREngine.fpr_double(FPREngine.fpr_mul(fpct_a_re, fpct_a_im));
//        return new ComplexNumberWrapper(fpct_d_re, fpct_d_im);
//    }

//    ComplexNumberWrapper FPC_INV(double a_re, double a_im)
//    {
//        double fpct_a_re, fpct_a_im;
//        double fpct_d_re, fpct_d_im;
//        double fpct_m;
//        fpct_a_re = (a_re);
//        fpct_a_im = (a_im);
//        fpct_m = FPREngine.fpr_add(FPREngine.fpr_sqr(fpct_a_re), FPREngine.fpr_sqr(fpct_a_im));
//        fpct_m = FPREngine.fpr_inv(fpct_m);
//        fpct_d_re = FPREngine.fpr_mul(fpct_a_re, fpct_m);
//        fpct_d_im = FPREngine.fpr_mul(FPREngine.fpr_neg(fpct_a_im), fpct_m);
//        return new ComplexNumberWrapper(fpct_d_re, fpct_d_im);
//    }

//    static ComplexNumberWrapper FPC_DIV(double a_re, double a_im, double b_re, double b_im)
//    {
//        double fpct_m = 1.0 / (b_re * b_re + b_im * b_im);
//        b_re = b_re * fpct_m;
//        b_im = -b_im * fpct_m;
//        return new ComplexNumberWrapper(a_re * b_re - a_im * b_im, a_re * b_im + a_im * b_re);
//    }

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
    static void FFT(double[] srcf, int f, int logn)
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
        int ht, hm, i1, j1;
        int j2, fj, fjhn, fjht, fjhthn;
        double s_re, s_im;
        double x_re, x_im, y_re, y_im, a_re, a_im;
        for (u = 1, m = 2; u < logn; u++, m <<= 1)
        {
            ht = t >> 1;
            hm = m >> 1;
            for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t)
            {
                j2 = j1 + ht + f;
                fj = ((m + i1) << 1);
                s_re = FPREngine.fpr_gm_tab[fj];
                s_im = FPREngine.fpr_gm_tab[fj + 1];
                for (fj = f + j1, fjhn = fj + hn, fjht = fj + ht, fjhthn = fjht + hn; fj < j2;
                     fj++, fjhn++, fjht++, fjhthn++)
                {
                    x_re = srcf[fj];
                    x_im = srcf[fjhn];
                    a_re = srcf[fjht];
                    a_im = srcf[fjhthn];
                    y_re = a_re * s_re - a_im * s_im;
                    y_im = a_re * s_im + a_im * s_re;
                    srcf[fj] = x_re + y_re;
                    srcf[fjhn] = x_im + y_im;
                    srcf[fjht] = x_re - y_re;
                    srcf[fjhthn] = x_im - y_im;
                }
            }
            t = ht;
        }
    }

    /* see inner.h */
    static void iFFT(double[] srcf, int f, int logn)
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
        int dt, hm, i1, j1;
        int j2, fj, fjhn, fjt, fjthn;
        double s_re, s_im;
        double x_re, x_im, y_re, y_im;
        n = 1 << logn;
        t = 1;
        m = n;
        hn = n >> 1;
        for (u = logn; u > 1; u--)
        {
            hm = m >> 1;
            dt = t << 1;
            for (i1 = 0, j1 = 0; j1 < hn; i1++, j1 += dt)
            {
                j2 = j1 + t + f;
                fj = (hm + i1) << 1;
                s_re = FPREngine.fpr_gm_tab[fj];
                s_im = -FPREngine.fpr_gm_tab[fj + 1];
                for (fj = f + j1, fjhn = fj + hn, fjt = fj + t, fjthn = fjt + hn; fj < j2;
                     fj++, fjhn++, fjt++, fjthn++)
                {
                    x_re = srcf[fj];
                    x_im = srcf[fjhn];
                    y_re = srcf[fjt];
                    y_im = srcf[fjthn];
                    srcf[fj] = x_re + y_re;
                    srcf[fjhn] = x_im + y_im;
                    x_re -= y_re;
                    x_im -= y_im;
                    srcf[fjt] = x_re * s_re - x_im * s_im;
                    srcf[fjthn] = x_re * s_im + x_im * s_re;
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
            double ni;

            ni = FPREngine.fpr_p2_tab[logn];
            for (u = 0; u < n; u++)
            {
                srcf[f + u] = srcf[f + u] * ni;
            }
        }
    }

    /* see inner.h */
    static void poly_add(
        double[] srca, int a, double[] srcb, int b, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            srca[a + u] += srcb[b + u];
        }
    }

    /* see inner.h */
    static void poly_sub(
        double[] srca, int a, double[] srcb, int b, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            srca[a + u] -= srcb[b + u];
        }
    }

    /* see inner.h */
    static void poly_neg(double[] srca, int a, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            srca[a + u] = -srca[a + u];
        }
    }

    /* see inner.h */
    static void poly_adj_fft(double[] srca, int a, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = (n >> 1); u < n; u++)
        {
            srca[a + u] = -srca[a + u];
        }
    }

    /* see inner.h */
    static void poly_mul_fft(
        double[] srca, int a, double[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        double a_re, a_im, b_re, b_im;
        int au, auhn, bu;
        for (u = 0, au = a, auhn = a + hn, bu = b; u < hn; u++, au++, bu++, auhn++)
        {
            a_re = srca[au];
            a_im = srca[auhn];
            b_re = srcb[bu];
            b_im = srcb[bu + hn];
            srca[au] = a_re * b_re - a_im * b_im;
            srca[auhn] = a_re * b_im + a_im * b_re;
        }
    }

    /* see inner.h */
    static void poly_muladj_fft(
        double[] srca, int a, double[] srcb, int b, int logn)
    {
        int n, hn, u, au;
        double a_re, a_im, b_re, b_im;
        n = 1 << logn;
        hn = n >> 1;
        for (u = 0, au = a; u < hn; u++, au++)
        {
            a_re = srca[au];
            a_im = srca[au + hn];
            b_re = srcb[b + u];
            b_im = srcb[b + u + hn];
            srca[au] = a_re * b_re + a_im * b_im;
            srca[au + hn] = a_im * b_re - a_re * b_im;
        }
    }

    /* see inner.h */
    static void poly_mulselfadj_fft(double[] srca, int a, int logn)
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
            double a_re, a_im;
            //ComplexNumberWrapper res;

            a_re = srca[a + u];
            a_im = srca[a + u + hn];
            srca[a + u] = a_re * a_re + a_im * a_im;
            srca[a + u + hn] = FPREngine.fpr_zero;
        }
    }

    /* see inner.h */
    static void poly_mulconst(double[] srca, int a, double x, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            srca[a + u] = srca[a + u] * x;
        }
    }

    /* see inner.h */
//    void poly_div_fft(
//        double[] srca, int a, double[] srcb, int b, int logn)
//    {
//        int n, hn, u;
//
//        n = 1 << logn;
//        hn = n >> 1;
//        for (u = 0; u < hn; u++)
//        {
//            double a_re, a_im, b_re, b_im;
//            ComplexNumberWrapper res;
//
//            a_re = srca[a + u];
//            a_im = srca[a + u + hn];
//            b_re = srcb[b + u];
//            b_im = srcb[b + u + hn];
//            res = FPC_DIV(a_re, a_im, b_re, b_im);
//            srca[a + u] = res.re;
//            srca[a + u + hn] = res.im;
//        }
//    }

    /* see inner.h */
    static void poly_invnorm2_fft(double[] srcd, int d,
                                  double[] srca, int a, double[] srcb, int b, int logn)
    {
        int n, hn, u;
        double a_re, a_im;
        double b_re, b_im;
        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {


            a_re = srca[a + u];
            a_im = srca[a + u + hn];
            b_re = srcb[b + u];
            b_im = srcb[b + u + hn];
            srcd[d + u] = 1.0 / (a_re * a_re + a_im * a_im +
                b_re * b_re + b_im * b_im);
        }
    }

    /* see inner.h */
    static void poly_add_muladj_fft(double[] srcd,
                                    double[] srcF, double[] srcG,
                                    double[] srcf, double[] srcg, int logn)
    {
        int n, hn, u;
        double F_re, F_im, G_re, G_im;
        double f_re, f_im, g_re, g_im;
        double a_re, a_im, b_re, b_im;
        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            int uhn = u + hn;
            F_re = srcF[u];
            F_im = srcF[uhn];
            G_re = srcG[u];
            G_im = srcG[uhn];
            f_re = srcf[u];
            f_im = srcf[uhn];
            g_re = srcg[u];
            g_im = srcg[uhn];

            a_re = F_re * f_re + F_im * f_im;
            a_im = F_im * f_re - F_re * f_im;
            b_re = G_re * g_re + G_im * g_im;
            b_im = G_im * g_re - G_re * g_im;
            srcd[u] = a_re + b_re;
            srcd[uhn] = a_im + b_im;
        }
    }

    /* see inner.h */
    static void poly_mul_autoadj_fft(
        double[] srca, int a, double[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            srca[a + u] *= srcb[b + u];
            srca[a + u + hn] *= srcb[b + u];
        }
    }

    /* see inner.h */
    static void poly_div_autoadj_fft(
        double[] srca, int a, double[] srcb, int b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            double ib = 1.0 / srcb[b + u];
            srca[a + u] *= ib;
            srca[a + u + hn] *= ib;
        }
    }

    /* see inner.h */
    static void poly_LDL_fft(
        double[] srcg00, int g00,
        double[] srcg01, int g01, double[] srcg11, int g11, int logn)
    {
        int n, hn, u, uhn, g01u, g01uhn;
        double g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
        n = 1 << logn;
        hn = n >> 1;
        for (u = 0, uhn = hn, g01u = g01, g01uhn = g01 + hn;
             u < hn; u++, uhn++, g01u++, g01uhn++)
        {
            g00_re = srcg00[g00 + u];
            g00_im = srcg00[g00 + uhn];
            g01_re = srcg01[g01u];
            g01_im = srcg01[g01uhn];

            g11_im = 1.0 / (g00_re * g00_re + g00_im * g00_im);
            g11_re = g00_re * g11_im;
            g11_im *= -g00_im;
            g00_re = g01_re * g11_re - g01_im * g11_im;
            g00_im = g01_re * g11_im + g01_im * g11_re;
            g11_re = g01_re;
            g11_im = g01_im;
            g01_re = g00_re * g11_re + g00_im * g11_im;
            g01_im = g00_re * -g11_im + g00_im * g11_re;
            srcg11[g11 + u] -= g01_re;
            srcg11[g11 + uhn] -= g01_im;
            srcg01[g01u] = g00_re;
            srcg01[g01uhn] = -g00_im;
        }
    }

    /* see inner.h */
//    void poly_LDLmv_fft(
//        double[] srcd11, int d11, double[] srcl10, int l10,
//        double[] srcg00, int g00, double[] srcg01, int g01,
//        double[] srcg11, int g11, int logn)
//    {
//        int n, hn, u;
//
//        n = 1 << logn;
//        hn = n >> 1;
//        for (u = 0; u < hn; u++)
//        {
//            double g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
//            double mu_re, mu_im;
//            ComplexNumberWrapper res;
//
//            g00_re = srcg00[g00 + u];
//            g00_im = srcg00[g00 + u + hn];
//            g01_re = srcg01[g01 + u];
//            g01_im = srcg01[g01 + u + hn];
//            g11_re = srcg11[g11 + u];
//            g11_im = srcg11[g11 + u + hn];
//            res = FPC_DIV(g01_re, g01_im, g00_re, g00_im);
//            mu_re = res.re;
//            mu_im = res.im;
//            res = FPC_MUL(mu_re, mu_im, g01_re, FPREngine.fpr_neg(g01_im));
//            g01_re = res.re;
//            g01_im = res.im;
//            res = FPC_SUB(g11_re, g11_im, g01_re, g01_im);
//            srcd11[d11 + u] = res.re;
//            srcd11[d11 + u + hn] = res.im;
//            srcl10[l10 + u] = mu_re;
//            srcl10[l10 + u + hn] = FPREngine.fpr_neg(mu_im);
//        }
//    }

    /* see inner.h */
    static void poly_split_fft(
        double[] srcf0, int f0, double[] srcf1, int f1,
        double[] srcf, int f, int logn)
    {
        /*
         * The FFT representation we use is in bit-reversed order
         * (element i contains f(w^(rev(i))), where rev() is the
         * bit-reversal function over the ring degree. This changes
         * indexes with regards to the Falcon specification.
         */
        int n, hn, qn, u;
        double a_re, a_im, b_re, b_im;
        double t_re, t_im;
        n = 1 << logn;
        hn = n >> 1;
        qn = hn >> 1;
        int idx;
        /*
         * We process complex values by pairs. For logn = 1, there is only
         * one complex value (the other one is the implicit conjugate),
         * so we add the two lines below because the loop will be
         * skipped.
         */
        srcf0[f0] = srcf[f];
        srcf1[f1] = srcf[f + hn];

        for (u = 0; u < qn; u++)
        {
            idx = f + (u << 1);
            a_re = srcf[idx];
            a_im = srcf[idx++ + hn];
            b_re = srcf[idx];
            b_im = srcf[idx + hn];

            srcf0[f0 + u] = (a_re + b_re) * 0.5;
            srcf0[f0 + u + qn] = (a_im + b_im) * 0.5;

            t_re = a_re - b_re;
            t_im = a_im - b_im;

            idx = ((u + hn) << 1);
            b_re = FPREngine.fpr_gm_tab[idx];
            b_im = -FPREngine.fpr_gm_tab[idx + 1];
            idx = f1 + u;
            srcf1[idx] = (t_re * b_re - t_im * b_im) * 0.5;
            srcf1[idx + qn] = (t_re * b_im + t_im * b_re) * 0.5;
        }
    }

    /* see inner.h */
    static void poly_merge_fft(
        double[] srcf, int f,
        double[] srcf0, int f0, double[] srcf1, int f1, int logn)
    {
        int n, hn, qn, u, idx;
        double a_re, a_im, b_re, b_im;
        double t_re, t_im;
        n = 1 << logn;
        hn = n >> 1;
        qn = hn >> 1;

        /*
         * An extra copy to handle the special case logn = 1.
         */
        srcf[f] = srcf0[f0];
        srcf[f + hn] = srcf1[f1];

        for (u = 0; u < qn; u++)
        {
            idx = f1 + u;
            a_re = srcf1[idx];
            a_im = srcf1[idx + qn];
            idx = ((u + hn) << 1);
            t_re = FPREngine.fpr_gm_tab[idx];
            t_im = FPREngine.fpr_gm_tab[idx + 1];
            b_re = a_re * t_re - a_im * t_im;
            b_im = a_re * t_im + a_im * t_re;

            idx = f0 + u;
            a_re = srcf0[idx];
            a_im = srcf0[idx + qn];

            idx = f + (u << 1);
            srcf[idx] = a_re + b_re;
            srcf[idx++ + hn] = a_im + b_im;

            srcf[idx] = a_re - b_re;
            srcf[idx + hn] = a_im - b_im;
        }
    }

}
