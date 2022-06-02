package org.bouncycastle.pqc.crypto.falcon;

/**
 * Fast Fourier transform implementation
 */
class FalconFFT
{

    FalconFprPoly fft;

    FalconFFT(FalconFprPoly f, int logn)
    {
        int u, t, n, hn, m;
        this.fft = new FalconFprPoly(f.coeffs);
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
                FalconFPR sre, sim;
                sre = FalconFPR.fpr_gm_tab[((m + i1) << 1) + 0];
                sim = FalconFPR.fpr_gm_tab[((m + i1) << 1) + 1];
                for (j = j1; j < j2; j++)
                {
                    FalconFPR xre, xim, yre, yim;
                    FalconFPR[] tmp;
                    xre = this.fft.coeffs[j];
                    xim = this.fft.coeffs[j + hn];
                    yre = this.fft.coeffs[j + ht];
                    yim = this.fft.coeffs[j + ht + hn];
                    tmp = c_mul(yre, yim, sre, sim);
                    yre = tmp[0];
                    yim = tmp[1];
                    tmp = c_add(xre, xim, yre, yim);
                    this.fft.coeffs[j] = tmp[0];
                    this.fft.coeffs[j + hn] = tmp[1];
                    tmp = c_sub(xre, xim, yre, yim);
                    this.fft.coeffs[j + ht] = tmp[0];
                    this.fft.coeffs[j + ht + hn] = tmp[1];
                }
            }
            t = ht;
        }
    }

    FalconFFT(int n)
    {
        this.fft = new FalconFprPoly(n);
    }

    FalconFprPoly iFFT(int logn)
    {
        int n, u, hn, t, m;
        n = 1 << logn;
        hn = n >> 1;
        t = 1;
        m = n;
        FalconFprPoly res = new FalconFprPoly(0);
        res.coeffs = this.fft.coeffs.clone();
        for (u = logn; u > 1; u--)
        {
            int hm, dt, i1, j1;
            hm = m >> 1;
            dt = t << 1;
            for (i1 = 0, j1 = 0; j1 < hn; i1++, j1 += dt)
            {
                int j, j2;
                j2 = j1 + t;
                FalconFPR sre, sim;
                sre = FalconFPR.fpr_gm_tab[((hm + i1) << 1) + 0];
                sim = FalconFPR.fpr_gm_tab[((hm + i1) << 1) + 1].neg();
                for (j = j1; j < j2; j++)
                {
                    FalconFPR xre, xim, yre, yim;
                    FalconFPR[] tmp;
                    xre = res.coeffs[j];
                    xim = res.coeffs[j + hn];
                    yre = res.coeffs[j + t];
                    yim = res.coeffs[j + t + hn];
                    tmp = c_add(xre, xim, yre, yim);
                    res.coeffs[j] = tmp[0];
                    res.coeffs[j + hn] = tmp[1];
                    tmp = c_sub(xre, xim, yre, yim);
                    xre = tmp[0];
                    xim = tmp[1];
                    tmp = c_mul(xre, xim, sre, sim);
                    res.coeffs[j + t] = tmp[0];
                    res.coeffs[j + t + hn] = tmp[1];
                }
            }
            t = dt;
            m = hm;
        }
        if (logn > 0)
        {
            FalconFPR ni;

            ni = FalconFPR.fpr_p2_tab[logn];
            for (u = 0; u < n; u++)
            {
                res.coeffs[u] = res.coeffs[u].mul(ni);
            }
        }
        return res;
    }

    void poly_add(FalconFFT b, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            this.fft.coeffs[u] = this.fft.coeffs[u].add(b.fft.coeffs[u]);
        }
    }

    void poly_sub(FalconFFT b, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            this.fft.coeffs[u] = this.fft.coeffs[u].sub(b.fft.coeffs[u]);
        }
    }

    void poly_neg(int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            this.fft.coeffs[u] = this.fft.coeffs[u].neg();
        }
    }

    void poly_adj(int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = (n >> 1); u < n; u++)
        {
            this.fft.coeffs[u] = this.fft.coeffs[u].neg();
        }
    }

    void poly_mul(FalconFFT b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            FalconFPR[] tmp;

            a_re = this.fft.coeffs[u];
            a_im = this.fft.coeffs[u + hn];
            b_re = b.fft.coeffs[u];
            b_im = b.fft.coeffs[u + hn];
            tmp = c_mul(a_re, a_im, b_re, b_im);
            this.fft.coeffs[u] = tmp[0];
            this.fft.coeffs[u + hn] = tmp[1];
        }
    }

    void poly_muladj(FalconFFT b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            FalconFPR[] tmp;

            a_re = this.fft.coeffs[u];
            a_im = this.fft.coeffs[u + hn];
            b_re = b.fft.coeffs[u];
            b_im = b.fft.coeffs[u + hn].neg();
            tmp = c_mul(a_re, a_im, b_re, b_im);
            this.fft.coeffs[u] = tmp[0];
            this.fft.coeffs[u + hn] = tmp[1];
        }
    }

    void poly_mulselfadj(int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im;

            a_re = this.fft.coeffs[u];
            a_im = this.fft.coeffs[u + hn];
            this.fft.coeffs[u] = a_re.sqr().add(a_im.sqr());
            this.fft.coeffs[u] = FalconFPR.fpr_zero;
        }
    }

    void poly_mulconst(FalconFPR x, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            this.fft.coeffs[u] = this.fft.coeffs[u].mul(x);
        }
    }

    void poly_div(FalconFFT b, int logn)
    {
        int n, hn, u;
        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            FalconFPR[] tmp;
            a_re = this.fft.coeffs[u];
            a_im = this.fft.coeffs[u + hn];
            b_re = b.fft.coeffs[u];
            b_im = b.fft.coeffs[u + hn];
            tmp = c_div(a_re, a_im, b_re, b_im);
            this.fft.coeffs[u] = tmp[0];
            this.fft.coeffs[u + hn] = tmp[1];
        }
    }

    static FalconFFT poly_invnorm2(FalconFFT a, FalconFFT b, int logn)
    {
        int n, hn, u;
        n = 1 << logn;
        hn = n >> 1;
        FalconFFT res = new FalconFFT(n);
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im;
            FalconFPR b_re, b_im;

            a_re = a.fft.coeffs[u];
            a_im = a.fft.coeffs[u + hn];
            b_re = b.fft.coeffs[u];
            b_im = b.fft.coeffs[u + hn];
            res.fft.coeffs[u] = a_re.sqr().add(a_im.sqr())
                .add(b_re.sqr().add(b_im.sqr()))
                .inv();
        }
        return res;
    }

    static FalconFFT poly_add_muladj(FalconFFT F, FalconFFT G,
                                     FalconFFT f, FalconFFT g, int logn)
    {
        int n, hn, u;
        n = 1 << logn;
        hn = n >> 1;
        FalconFFT res = new FalconFFT(n);
        for (u = 0; u < hn; u++)
        {
            FalconFPR F_re, F_im, G_re, G_im;
            FalconFPR f_re, f_im, g_re, g_im;
            FalconFPR a_re, a_im, b_re, b_im;
            FalconFPR[] tmp;

            F_re = F.fft.coeffs[u];
            F_im = F.fft.coeffs[u + hn];
            G_re = G.fft.coeffs[u];
            G_im = G.fft.coeffs[u + hn];
            f_re = f.fft.coeffs[u];
            f_im = f.fft.coeffs[u + hn];
            g_re = g.fft.coeffs[u];
            g_im = g.fft.coeffs[u + hn];

            tmp = c_mul(F_re, F_im, f_re, f_im.neg());
            a_re = tmp[0];
            a_im = tmp[1];
            tmp = c_mul(G_re, G_im, g_re, g_im.neg());
            b_re = tmp[0];
            b_im = tmp[1];

            res.fft.coeffs[u] = a_re.add(b_re);
            res.fft.coeffs[u + hn] = a_im.add(b_im);
        }
        return res;
    }

    void poly_mul_autoadj(FalconFFT b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            this.fft.coeffs[u] = this.fft.coeffs[u].mul(b.fft.coeffs[u]);
            this.fft.coeffs[u + hn] = this.fft.coeffs[u + hn].mul(b.fft.coeffs[u]);
        }
    }

    void poly_div_autoadj(FalconFFT b, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR ib;
            ib = b.fft.coeffs[u].inv();
            this.fft.coeffs[u] = this.fft.coeffs[u].mul(ib);
            this.fft.coeffs[u + hn] = this.fft.coeffs[u + hn].mul(ib);
        }
    }

    /*
     * functions for complex numbers
     */

    static FalconFPR[] c_add(FalconFPR are, FalconFPR aim, FalconFPR bre, FalconFPR bim)
    {
        FalconFPR[] res = new FalconFPR[2];
        res[0] = are.add(bre);
        res[1] = aim.add(bim);
        return res;
    }

    static FalconFPR[] c_sub(FalconFPR are, FalconFPR aim, FalconFPR bre, FalconFPR bim)
    {
        FalconFPR[] res = new FalconFPR[2];
        res[0] = are.sub(bre);
        res[1] = aim.sub(bim);
        return res;
    }

    static FalconFPR[] c_mul(FalconFPR are, FalconFPR aim, FalconFPR bre, FalconFPR bim)
    {
        FalconFPR[] res = new FalconFPR[2];
        res[0] = are.mul(bre).sub(aim.mul(bim));
        res[1] = are.mul(bim).add(aim.mul(bre));
        return res;
    }

    static FalconFPR[] c_sqr(FalconFPR are, FalconFPR aim)
    {
        return c_mul(are, aim, are, aim);
    }

    static FalconFPR[] c_inv(FalconFPR are, FalconFPR aim)
    {
        FalconFPR[] res = new FalconFPR[2];
        FalconFPR m;
        m = are.sqr().add(aim.sqr());
        m = m.inv();
        res[0] = are.mul(m);
        res[1] = aim.neg().mul(m);
        return res;
    }

    static FalconFPR[] c_div(FalconFPR are, FalconFPR aim, FalconFPR bre, FalconFPR bim)
    {
        FalconFPR[] res = new FalconFPR[2];
        FalconFPR m, br, bi, ar, ai;
        ar = are;
        ai = aim;
        br = bre;
        bi = bim;
        m = br.sqr().add(bi.sqr());
        m = m.inv();
        br = br.mul(m);
        bi = bi.neg().mul(m);
        res[0] = ar.mul(br).sub(ai.mul(bi));
        res[1] = ar.mul(bi).add(ai.mul(br));
        return res;
    }

    // not using our own data structure but keeping to basic arrays for easier translation from reference code

    static void fft(int fp, FalconFPR[] fdata, int logn)
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

                s_re = FalconFPR.fpr_gm_tab[((m + i1) << 1) + 0];
                s_im = FalconFPR.fpr_gm_tab[((m + i1) << 1) + 1];
                for (j = j1; j < j2; j++)
                {
                    FalconFPR x_re, x_im, y_re, y_im;

                    x_re = fdata[fp + j];
                    x_im = fdata[fp + j + hn];
                    y_re = fdata[fp + j + ht];
                    y_im = fdata[fp + j + ht + hn];
                    FalconFPR[] r;
                    r = c_mul(y_re, y_im, s_re, s_im);
                    y_re = r[0];
                    y_im = r[1];
                    r = c_add(x_re, x_im, y_re, y_im);
                    fdata[fp + j] = r[0];
                    fdata[fp + j + hn] = r[1];
                    r = c_sub(x_re, x_im, y_re, y_im);
                    fdata[fp + j + ht] = r[0];
                    fdata[fp + j + ht + hn] = r[1];
                }
            }
            t = ht;
        }
    }

    static void ifft(int fp, FalconFPR[] fdata, int logn)
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

                s_re = FalconFPR.fpr_gm_tab[((hm + i1) << 1) + 0];
                s_im = FalconFPR.fpr_gm_tab[((hm + i1) << 1) + 1].neg();
                for (j = j1; j < j2; j++)
                {
                    FalconFPR x_re, x_im, y_re, y_im;
                    FalconFPR[] r;

                    x_re = fdata[fp + j];
                    x_im = fdata[fp + j + hn];
                    y_re = fdata[fp + j + t];
                    y_im = fdata[fp + j + t + hn];
                    r = c_add(x_re, x_im, y_re, y_im);
                    fdata[fp + j] = r[0];
                    fdata[fp + j + hn] = r[1];
                    r = c_sub(x_re, x_im, y_re, y_im);
                    x_re = r[0];
                    x_im = r[1];
                    r = c_mul(x_re, x_im, s_re, s_im);
                    fdata[fp + j + t] = r[0];
                    fdata[fp + j + t + hn] = r[1];
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

            ni = FalconFPR.fpr_p2_tab[logn];
            for (u = 0; u < n; u++)
            {
                fdata[fp + u] = fdata[fp + u].mul(ni);
            }
        }
    }

    static void poly_invnorm2_fft(int dp, FalconFPR[] ddata, int a, FalconFPR[] adata, int b, FalconFPR[] bdata, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im;
            FalconFPR b_re, b_im;

            a_re = adata[a + u];
            a_im = adata[a + u + hn];
            b_re = bdata[b + u];
            b_im = bdata[b + u + hn];
            ddata[dp + u] = a_re.sqr().add(a_im.sqr()).add(b_re.sqr().add(b_im.sqr())).inv();
        }
    }

    static void poly_adj_fft(int a, FalconFPR[] adata, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = (n >> 1); u < n; u++)
        {
            adata[a + u] = adata[a + u].neg();
        }
    }

    static void poly_mul_fft(int a, FalconFPR[] adata, int b, FalconFPR[] bdata, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR a_re, a_im, b_re, b_im;
            FalconFPR[] r;

            a_re = adata[a + u];
            a_im = adata[a + u + hn];
            b_re = bdata[b + u];
            b_im = bdata[b + u + hn];
            r = c_mul(a_re, a_im, b_re, b_im);
            adata[a + u] = r[0];
            adata[a + u + hn] = r[1];
        }
    }

    static void poly_add(int a, FalconFPR[] adata, int b, FalconFPR[] bdata, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            adata[a + u] = adata[a + u].add(bdata[b + u]);
        }
    }

    static void poly_sub(int a, FalconFPR[] adata, int b, FalconFPR[] bdata, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            adata[a + u] = adata[a + u].sub(bdata[b + u]);
        }
    }

    static void poly_mul_autoadj_fft(int a, FalconFPR[] adata, int b, FalconFPR[] bdata, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            adata[a + u] = adata[a + u].mul(bdata[b + u]);
            adata[a + u + hn] = adata[a + u + hn].mul(bdata[b + u]);
        }
    }

    static void poly_add_muladj_fft(int d, FalconFPR[] ddata,
                                    int F, FalconFPR[] Fdata, int G, FalconFPR[] Gdata,
                                    int f, FalconFPR[] fdata, int g, FalconFPR[] gdata, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR F_re, F_im, G_re, G_im;
            FalconFPR f_re, f_im, g_re, g_im;
            FalconFPR a_re, a_im, b_re, b_im;
            FalconFPR[] r;

            F_re = Fdata[F + u];
            F_im = Fdata[F + u + hn];
            G_re = Gdata[G + u];
            G_im = Gdata[G + u + hn];
            f_re = fdata[f + u];
            f_im = fdata[f + u + hn];
            g_re = gdata[g + u];
            g_im = gdata[g + u + hn];

            r = c_mul(F_re, F_im, f_re, f_im.neg());
            a_re = r[0];
            a_im = r[1];
            r = c_mul(G_re, G_im, g_re, g_im.neg());
            b_re = r[0];
            b_im = r[1];
            ddata[d + u] = a_re.add(b_re);
            ddata[d + u + hn] = a_im.add(b_im);
        }
    }

    static void poly_div_autoadj_fft(int a, FalconFPR[] ad, int b, FalconFPR[] bd, int logn)
    {
        int n, hn, u;

        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR ib;

            ib = bd[b + u].inv();
            ad[a + u] = ad[a + u].mul(ib);
            ad[a + u + hn] = ad[a + u + hn].mul(ib);
        }
    }

    static void poly_LDL_fft(int g00, FalconFPR[] g00a, int g01, FalconFPR[] g01a,
                             int g11, FalconFPR[] g11a, int logn)
    {
        int n, hn, u;
        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
            FalconFPR mu_re, mu_im;
            FalconFPR[] r;
            g00_re = g00a[g00 + u];
            g00_im = g00a[g00 + u + hn];
            g01_re = g01a[g01 + u];
            g01_im = g01a[g01 + u + hn];
            g11_re = g11a[g11 + u];
            g11_im = g11a[g11 + u + hn];
            //FPC_DIV(mu_re, mu_im, g01_re, g01_im, g00_re, g00_im);
            r = c_div(g01_re, g01_im, g00_re, g00_im);
            mu_re = r[0];
            mu_im = r[1];
            //FPC_MUL(g01_re, g01_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
            r = c_mul(mu_re, mu_im, g01_re, g01_im.neg());
            g01_re = r[0];
            g01_im = r[1];
            //FPC_SUB(g11[u], g11[u + hn], g11_re, g11_im, g01_re, g01_im);
            r = c_sub(g11_re, g11_im, g01_re, g01_im);
            g11a[g11 + u] = r[0];
            g11a[g11 + u + hn] = r[1];
            g01a[g01 + u] = mu_re;
            g01a[g01 + u + hn] = mu_im.neg();
        }
    }

    static void poly_LDLmv_fft(int d11, FalconFPR[] d11a, int l10, FalconFPR[] l10a,
                               int g00, FalconFPR[] g00a, int g01, FalconFPR[] g01a,
                               int g11, FalconFPR[] g11a, int logn)
    {
        int n, hn, u;
        n = 1 << logn;
        hn = n >> 1;
        for (u = 0; u < hn; u++)
        {
            FalconFPR g00_re, g00_im, g01_re, g01_im, g11_re, g11_im;
            FalconFPR mu_re, mu_im;
            FalconFPR[] r;
            g00_re = g00a[g00 + u];
            g00_im = g00a[g00 + u + hn];
            g01_re = g01a[g01 + u];
            g01_im = g01a[g01 + u + hn];
            g11_re = g11a[g11 + u];
            g11_im = g11a[g11 + u + hn];
            //FPC_DIV(mu_re, mu_im, g01_re, g01_im, g00_re, g00_im);
            r = c_div(g01_re, g01_im, g00_re, g00_im);
            mu_re = r[0];
            mu_im = r[1];
            //FPC_MUL(g01_re, g01_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
            r = c_mul(mu_re, mu_im, g01_re, g01_im.neg());
            g01_re = r[0];
            g01_im = r[1];
            //FPC_SUB(d11[u], d11[u + hn], g11_re, g11_im, g01_re, g01_im);
            r = c_sub(g11_re, g11_im, g01_re, g01_im);
            d11a[d11 + u] = r[0];
            d11a[d11 + u + hn] = r[1];
            l10a[l10 + u] = mu_re;
            l10a[l10 + u + hn] = mu_im.neg();
        }
    }

}
