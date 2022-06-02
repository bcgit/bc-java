package org.bouncycastle.pqc.crypto.falcon;

class FalconEngine
{
    private static byte[] max_fg_bits = {
        0, /* unused */
        8,
        8,
        8,
        8,
        8,
        7,
        7,
        6,
        6,
        5
    };

    private static byte[] max_FG_bits = {
        0, /* unused */
        8,
        8,
        8,
        8,
        8,
        8,
        8,
        8,
        8,
        8
    };

    private static int[] MAX_BL_SMALL = {
        1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209
    };

    private static int[] MAX_BL_LARGE = {
        2, 2, 5, 7, 12, 21, 40, 78, 157, 308
    };

    private static int[] TMP_SIZE = {
        0,
        136,
        272,
        224,
        448,
        896,
        1792,
        3584,
        7168,
        14336,
        28672
    };

    private static final int DEPTH_INT_FG = 4;
    private final int logn;

    FalconEngine(int logn)
    {
        this.logn = logn;
    }

    FalconKeys keygen(FalconSHAKE256 random)
    {
//        System.out.println("Starting keygen...");
        int n, u;
        int logn = this.logn;
        n = 1 << logn;
        FalconSmallPoly
            f = new FalconSmallPoly(n),
            g = new FalconSmallPoly(n),
            F = new FalconSmallPoly(n),
            G = new FalconSmallPoly(n);
        FalconShortPoly
            h = new FalconShortPoly(n);
        for (; ; )
        {
            FalconFprPoly rt1, rt2;
            FalconFFT rt1_fft, rt2_fft, rt3;
            FalconFPR bnorm;
            int normf, normg, norm;
            int lim;
            /*
             * The poly_small_mkgauss() function makes sure
             * that the sum of coefficients is 1 modulo 2
             * (i.e. the resultant of the polynomial with phi
             * will be odd).
             */
//            System.out.println("creating f, g...");
            f.poly_mkgauss(random, logn);
            g.poly_mkgauss(random, logn);
//            System.out.println("created f, g.");
            /*
             * Verify that all coefficients are within the bounds
             * defined in max_fg_bits. This is the case with
             * overwhelming probability; this guarantees that the
             * key will be encodable with FALCON_COMP_TRIM.
             */
//            System.out.println("checking f,g bounds...");
            lim = 1 << (max_fg_bits[logn] - 1);
            for (u = 0; u < n; u++)
            {
                /*
                 * We can use non-CT tests since on any failure
                 * we will discard f and g.
                 */
                if (f.coeffs[u] >= lim || f.coeffs[u] <= -lim
                    || g.coeffs[u] >= lim || g.coeffs[u] <= -lim)
                {
                    lim = -1;
                    break;
                }
            }
            if (lim < 0)
            {
//                System.out.println("f,g out of bounds.");
                continue;
            }
//            System.out.println("checked f,g bounds.");
            /*
             * Bound is 1.17*sqrt(q). We compute the squared
             * norms. With q = 12289, the squared bound is:
             *   (1.17^2)* 12289 = 16822.4121
             * Since f and g are integral, the squared norm
             * of (g,-f) is an integer.
             */
//            System.out.println("checking norm...");
            normf = f.sqnorm(logn);
            normg = g.sqnorm(logn);
            norm = (normf + normg) | -((normf | normg) >>> 31);
            if (Integer.compareUnsigned(norm, 16823) >= 0)
            {
//                System.out.println("norm too big.");
                continue;
            }
//            System.out.println("checked norm.");
            /*
             * We compute the orthogonalized vector norm.
             */
//            System.out.println("checking orthogonal norm...");
            rt1 = new FalconFprPoly(f, logn);
            rt2 = new FalconFprPoly(g, logn);
            rt1_fft = new FalconFFT(rt1, logn);
            rt2_fft = new FalconFFT(rt2, logn);
            rt3 = FalconFFT.poly_invnorm2(rt1_fft, rt2_fft, logn);
            rt1_fft.poly_adj(logn);
            rt2_fft.poly_adj(logn);
            rt1_fft.poly_mulconst(FalconFPR.fpr_q, logn);
            rt2_fft.poly_mulconst(FalconFPR.fpr_q, logn);
            rt1_fft.poly_mul_autoadj(rt3, logn);
            rt2_fft.poly_mul_autoadj(rt3, logn);
            rt1 = rt1_fft.iFFT(logn);
            rt2 = rt2_fft.iFFT(logn);
            bnorm = FalconFPR.fpr_zero;
            for (u = 0; u < n; u++)
            {
                bnorm = bnorm.add(rt1.coeffs[u].sqr());
                bnorm = bnorm.add(rt2.coeffs[u].sqr());
            }
            if (!bnorm.lt(FalconFPR.fpr_bnorm_max))
            {
//                System.out.println("orthogonal norm too big.");
                continue;
            }
//            System.out.println("checked orthogonal norm.");
            /*
             * Compute public key h = g/f mod X^N+1 mod q. If this
             * fails, we must restart.
             */
//            System.out.println("computing public key...");
            if (!FalconShortPoly.compute_public(h, f, g, logn))
            {
//                System.out.println("no public key.");
                continue;
            }
//            System.out.println("public key made.");
            /*
             * Solve the NTRU equation to get F and G.
             */
            lim = (1 << (max_FG_bits[logn] - 1)) - 1;
            if (!this.solve_NTRU(logn, F, G, f, g, lim))
            {
                continue;
            }

            /*
             * Key pair is generated.
             */
            break;
        }
//        System.out.println("Finished keygen.");
        return new FalconKeys(f, g, F, G, h);
    }

    boolean solve_NTRU(int logn, FalconSmallPoly Fout, FalconSmallPoly Gout,
                       FalconSmallPoly f, FalconSmallPoly g, int lim)
    {
//        System.out.println("Starting NTRU solve...");
        int n, u;
        byte[] tmp = new byte[TMP_SIZE[logn]];
        int[] tmp_int = FalconTmp.byte_int(tmp);
        tmp = null;
        n = 1 << logn;
        int p, p0i, r;
        FalconSmallPrime[] primes;

        if (!this.solve_NTRU_deepest(logn, f, g, 0, tmp_int))
        {
//            System.out.println("Aborting NTRU solve - deepest.");
            return false;
        }
        /*
         * For logn <= 2, we need to use solve_NTRU_intermediate()
         * directly, because coefficients are a bit too large and
         * do not fit the hypotheses in solve_NTRU_binary_depth0().
         */
        if (logn <= 2)
        {
            int depth;

            depth = logn;
            while (depth-- > 0)
            {
                if (!solve_NTRU_intermediate(logn, f, g, depth, 0, tmp_int))
                {
//                    System.out.println(String.format("Aborting NTRU solve. - intermediate depth %d",depth));
                    return false;
                }
            }
        }
        else
        {
            int depth;

            depth = logn;
            while (depth-- > 2)
            {
                if (!solve_NTRU_intermediate(logn, f, g, depth, 0, tmp_int))
                {
//                    System.out.println(String.format("Aborting NTRU solve. - intermediate depth %d",depth));
                    return false;
                }
            }
            if (!solve_NTRU_binary_depth1(logn, f, g, 0, tmp_int))
            {
//                System.out.println("Aborting NTRU solve. - depth 1");
                return false;
            }
            if (!solve_NTRU_binary_depth0(logn, f, g, 0, tmp_int))
            {
//                System.out.println("Aborting NTRU solve. - depth 0");
                return false;
            }
        }

        /*
         * Final F and G are in fk->tmp, one word per coefficient
         * (signed value over 31 bits).
         */
        if (!FalconSmallPoly.big_to_small(Fout, 0, tmp_int, lim, logn)
            || !FalconSmallPoly.big_to_small(Gout, n, tmp_int, lim, logn))
        {
//            System.out.println("Aborting NTRU solve. - F,G too big");
            return false;
        }

        /*
         * Verify that the NTRU equation is fulfilled. Since all elements
         * have short lengths, verifying modulo a small prime p works, and
         * allows using the NTT.
         *
         * We put Gt[] first in tmp[], and process it first, so that it does
         * not overlap with G[] in case we allocated it ourselves.
         */
        int
            Gt = 0,
            ft = Gt + n,
            gt = ft + n,
            Ft = gt + n,
            gm = Ft + n;

        primes = FalconSmallPrime.PRIMES;
        p = primes[0].p;
        p0i = FalconCommon.modp_ninv31(p);
        FalconCommon.modp_mkgm2(gm, 0, tmp_int, logn, primes[0].g, p, p0i);
        for (u = 0; u < n; u++)
        {
            tmp_int[Gt + u] = FalconCommon.modp_set(Gout.coeffs[u], p);
        }
        for (u = 0; u < n; u++)
        {
            tmp_int[ft + u] = FalconCommon.modp_set(f.coeffs[u], p);
            tmp_int[gt + u] = FalconCommon.modp_set(g.coeffs[u], p);
            tmp_int[Ft + u] = FalconCommon.modp_set(Fout.coeffs[u], p);
        }
        FalconNTT.modp_NTT2(ft, tmp_int, gm, tmp_int, logn, p, p0i);
        FalconNTT.modp_NTT2(gt, tmp_int, gm, tmp_int, logn, p, p0i);
        FalconNTT.modp_NTT2(Ft, tmp_int, gm, tmp_int, logn, p, p0i);
        FalconNTT.modp_NTT2(Gt, tmp_int, gm, tmp_int, logn, p, p0i);
        r = FalconCommon.modp_montymul(12289, 1, p, p0i);
        for (u = 0; u < n; u++)
        {
            int z;

            z = FalconCommon.modp_sub(FalconCommon.modp_montymul(tmp_int[ft + u], tmp_int[Gt + u], p, p0i),
                FalconCommon.modp_montymul(tmp_int[gt + u], tmp_int[Ft + u], p, p0i), p);
            if (z != r)
            {
//                System.out.println("Aborting NTRU solve. - failed check");
                return false;
            }
        }
//        System.out.println("Finished NTRU solve.");
        return true;
    }

    boolean solve_NTRU_binary_depth0(int logn, FalconSmallPoly f, FalconSmallPoly g, int tp, int[] tmp)
    {
        int n, hn, u;
        int p, p0i, R2;
        int
            Fp,
            Gp,
            t1,
            t2,
            t3,
            t4,
            t5;
        int gm, igm, ft, gt;

        n = 1 << logn;
        hn = n >> 1;

        /*
         * Equations are:
         *
         *   f' = f0^2 - X^2*f1^2
         *   g' = g0^2 - X^2*g1^2
         *   F' and G' are a solution to f'G' - g'F' = q (from deeper levels)
         *   F = F'*(g0 - X*g1)
         *   G = G'*(f0 - X*f1)
         *
         * f0, f1, g0, g1, f', g', F' and G' are all "compressed" to
         * degree N/2 (their odd-indexed coefficients are all zero).
         *
         * Everything should fit in 31-bit integers, hence we can just use
         * the first small prime p = 2147473409.
         */
        p = FalconSmallPrime.PRIMES[0].p;
        p0i = FalconCommon.modp_ninv31(p);
        R2 = FalconCommon.modp_R2(p, p0i);

        Fp = tp;
        Gp = Fp + hn;
        ft = Gp + hn;
        gt = ft + n;
        gm = gt + n;
        igm = gm + n;

        FalconCommon.modp_mkgm2(gm, igm, tmp, logn, FalconSmallPrime.PRIMES[0].g, p, p0i);

        /*
         * Convert F' anf G' in NTT representation.
         */
        for (u = 0; u < hn; u++)
        {
            tmp[Fp + u] = FalconCommon.modp_set(FalconBigInt.one_to_plain(Fp + u, tmp), p);
            tmp[Gp + u] = FalconCommon.modp_set(FalconBigInt.one_to_plain(Gp + u, tmp), p);
        }
        FalconNTT.modp_NTT2(Fp, tmp, gm, tmp, logn - 1, p, p0i);
        FalconNTT.modp_NTT2(Gp, tmp, gm, tmp, logn - 1, p, p0i);

        /*
         * Load f and g and convert them to NTT representation.
         */
        for (u = 0; u < n; u++)
        {
            tmp[ft + u] = FalconCommon.modp_set(f.coeffs[u], p);
            tmp[gt + u] = FalconCommon.modp_set(g.coeffs[u], p);
        }
        FalconNTT.modp_NTT2(ft, tmp, gm, tmp, logn, p, p0i);
        FalconNTT.modp_NTT2(gt, tmp, gm, tmp, logn, p, p0i);

        /*
         * Build the unreduced F,G in ft and gt.
         */
        for (u = 0; u < n; u += 2)
        {
            int ftA, ftB, gtA, gtB;
            int mFp, mGp;

            ftA = tmp[ft + u + 0];
            ftB = tmp[ft + u + 1];
            gtA = tmp[gt + u + 0];
            gtB = tmp[gt + u + 1];
            mFp = FalconCommon.modp_montymul(tmp[Fp + (u >> 1)], R2, p, p0i);
            mGp = FalconCommon.modp_montymul(tmp[Gp + (u >> 1)], R2, p, p0i);
            tmp[ft + u + 0] = FalconCommon.modp_montymul(gtB, mFp, p, p0i);
            tmp[ft + u + 1] = FalconCommon.modp_montymul(gtA, mFp, p, p0i);
            tmp[gt + u + 0] = FalconCommon.modp_montymul(ftB, mGp, p, p0i);
            tmp[gt + u + 1] = FalconCommon.modp_montymul(ftA, mGp, p, p0i);
        }
        FalconNTT.modp_iNTT2(ft, tmp, igm, tmp, logn, p, p0i);
        FalconNTT.modp_iNTT2(gt, tmp, igm, tmp, logn, p, p0i);

        Gp = Fp + n;
        t1 = Gp + n;
        // memmove(Fp, ft, 2 * n * sizeof *ft);
        System.arraycopy(tmp, ft, tmp, Fp, 2 * n);

        /*
         * We now need to apply the Babai reduction. At that point,
         * we have F and G in two n-word arrays.
         *
         * We can compute F*adj(f)+G*adj(g) and f*adj(f)+g*adj(g)
         * modulo p, using the NTT. We still move memory around in
         * order to save RAM.
         */
        t2 = t1 + n;
        t3 = t2 + n;
        t4 = t3 + n;
        t5 = t4 + n;

        /*
         * Compute the NTT tables in t1 and t2. We do not keep t2
         * (we'll recompute it later on).
         */
        FalconCommon.modp_mkgm2(t1, t2, tmp, logn, FalconSmallPrime.PRIMES[0].g, p, p0i);

        /*
         * Convert F and G to NTT.
         */
        FalconNTT.modp_NTT2(Fp, tmp, t1, tmp, logn, p, p0i);
        FalconNTT.modp_NTT2(Gp, tmp, t1, tmp, logn, p, p0i);

        /*
         * Load f and adj(f) in t4 and t5, and convert them to NTT
         * representation.
         */
        tmp[t4] = tmp[t5] = FalconCommon.modp_set(f.coeffs[0], p);
        for (u = 1; u < n; u++)
        {
            tmp[t4 + u] = FalconCommon.modp_set(f.coeffs[u], p);
            tmp[t5 + n - u] = FalconCommon.modp_set(-f.coeffs[u], p);
        }
        FalconNTT.modp_NTT2(t4, tmp, t1, tmp, logn, p, p0i);
        FalconNTT.modp_NTT2(t5, tmp, t1, tmp, logn, p, p0i);

        /*
         * Compute F*adj(f) in t2, and f*adj(f) in t3.
         */
        for (u = 0; u < n; u++)
        {
            int w;

            w = FalconCommon.modp_montymul(tmp[t5 + u], R2, p, p0i);
            tmp[t2 + u] = FalconCommon.modp_montymul(w, tmp[Fp + u], p, p0i);
            tmp[t3 + u] = FalconCommon.modp_montymul(w, tmp[t4 + u], p, p0i);
        }

        /*
         * Load g and adj(g) in t4 and t5, and convert them to NTT
         * representation.
         */
        tmp[t4] = tmp[t5] = FalconCommon.modp_set(g.coeffs[0], p);
        for (u = 1; u < n; u++)
        {
            tmp[t4 + u] = FalconCommon.modp_set(g.coeffs[u], p);
            tmp[t5 + n - u] = FalconCommon.modp_set(-g.coeffs[u], p);
        }
        FalconNTT.modp_NTT2(t4, tmp, t1, tmp, logn, p, p0i);
        FalconNTT.modp_NTT2(t5, tmp, t1, tmp, logn, p, p0i);

        /*
         * Add G*adj(g) to t2, and g*adj(g) to t3.
         */
        for (u = 0; u < n; u++)
        {
            int w;

            w = FalconCommon.modp_montymul(tmp[t5 + u], R2, p, p0i);
            tmp[t2 + u] = FalconCommon.modp_add(tmp[t2 + u],
                FalconCommon.modp_montymul(w, tmp[Gp + u], p, p0i), p);
            tmp[t3 + u] = FalconCommon.modp_add(tmp[t3 + u],
                FalconCommon.modp_montymul(w, tmp[t4 + u], p, p0i), p);
        }

        /*
         * Convert back t2 and t3 to normal representation (normalized
         * around 0), and then
         * move them to t1 and t2. We first need to recompute the
         * inverse table for NTT.
         */
        FalconCommon.modp_mkgm2(t1, t4, tmp, logn, FalconSmallPrime.PRIMES[0].g, p, p0i);
        FalconNTT.modp_iNTT2(t2, tmp, t4, tmp, logn, p, p0i);
        FalconNTT.modp_iNTT2(t3, tmp, t4, tmp, logn, p, p0i);
        for (u = 0; u < n; u++)
        {
            tmp[t1 + u] = (int)FalconCommon.modp_norm(tmp[t2 + u], p);
            tmp[t2 + u] = (int)FalconCommon.modp_norm(tmp[t3 + u], p);
        }

        /*
         * At that point, array contents are:
         *
         *   F (NTT representation) (Fp)
         *   G (NTT representation) (Gp)
         *   F*adj(f)+G*adj(g) (t1)
         *   f*adj(f)+g*adj(g) (t2)
         *
         * We want to divide t1 by t2. The result is not integral; it
         * must be rounded. We thus need to use the FFT.
         */

        /*
         * Get f*adj(f)+g*adj(g) in FFT representation. Since this
         * polynomial is auto-adjoint, all its coordinates in FFT
         * representation are actually real, so we can truncate off
         * the imaginary parts.
         */
        FalconFPR[]
            tmp2 = new FalconFPR[3 * n];
        int rt1, rt2, rt3;
        rt1 = 0;
        rt2 = rt1 + n;
        rt3 = rt2 + n;
        // rt3 = align_fpr(tmp, t3);
        for (u = 0; u < n; u++)
        {
            tmp2[rt3 + u] = FalconFPR.fpr_of(tmp[t2 + u]);
        }
        FalconFFT.fft(rt3, tmp2, logn);
        // rt2 = align_fpr(tmp, t2);
        // memmove(rt2, rt3, hn * sizeof *rt3);
        System.arraycopy(tmp2, rt3, tmp2, rt2, hn);

        /*
         * Convert F*adj(f)+G*adj(g) in FFT representation.
         */
        rt3 = rt2 + hn;
        for (u = 0; u < n; u++)
        {
            tmp2[rt3 + u] = FalconFPR.fpr_of(tmp[t1 + u]);
        }
        FalconFFT.fft(rt3, tmp2, logn);

        /*
         * Compute (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g)) and get
         * its rounded normal representation in t1.
         */
        FalconFFT.poly_div_autoadj_fft(rt3, tmp2, rt2, tmp2, logn);
        FalconFFT.ifft(rt3, tmp2, logn);
        for (u = 0; u < n; u++)
        {
            tmp[t1 + u] = FalconCommon.modp_set((int)tmp2[rt3 + u].rint(), p);
        }

        /*
         * RAM contents are now:
         *
         *   F (NTT representation) (Fp)
         *   G (NTT representation) (Gp)
         *   k (t1)
         *
         * We want to compute F-k*f, and G-k*g.
         */
        t2 = t1 + n;
        t3 = t2 + n;
        t4 = t3 + n;
        t5 = t4 + n;
        FalconCommon.modp_mkgm2(t2, t3, tmp, logn, FalconSmallPrime.PRIMES[0].g, p, p0i);
        for (u = 0; u < n; u++)
        {
            tmp[t4 + u] = FalconCommon.modp_set(f.coeffs[u], p);
            tmp[t5 + u] = FalconCommon.modp_set(g.coeffs[u], p);
        }
        FalconNTT.modp_NTT2(t1, tmp, t2, tmp, logn, p, p0i);
        FalconNTT.modp_NTT2(t4, tmp, t2, tmp, logn, p, p0i);
        FalconNTT.modp_NTT2(t5, tmp, t2, tmp, logn, p, p0i);
        for (u = 0; u < n; u++)
        {
            int kw;

            kw = FalconCommon.modp_montymul(tmp[t1 + u], R2, p, p0i);
            tmp[Fp + u] = FalconCommon.modp_sub(tmp[Fp + u],
                FalconCommon.modp_montymul(kw, tmp[t4 + u], p, p0i), p);
            tmp[Gp + u] = FalconCommon.modp_sub(tmp[Gp + u],
                FalconCommon.modp_montymul(kw, tmp[t5 + u], p, p0i), p);
        }
        FalconNTT.modp_iNTT2(Fp, tmp, t3, tmp, logn, p, p0i);
        FalconNTT.modp_iNTT2(Gp, tmp, t3, tmp, logn, p, p0i);
        for (u = 0; u < n; u++)
        {
            tmp[Fp + u] = FalconCommon.modp_norm(tmp[Fp + u], p);
            tmp[Gp + u] = FalconCommon.modp_norm(tmp[Gp + u], p);
        }

        return true;
    }

    boolean solve_NTRU_binary_depth1(int logn_top, FalconSmallPoly f, FalconSmallPoly g, int tp, int[] tmp)
    {
        /*
         * The first half of this function is a copy of the corresponding
         * part in solve_NTRU_intermediate(), for the reconstruction of
         * the unreduced F and G. The second half (Babai reduction) is
         * done differently, because the unreduced F and G fit in 53 bits
         * of precision, allowing a much simpler process with lower RAM
         * usage.
         */
        int depth, logn;
        int n_top, n, hn, slen, dlen, llen, u;
        int
            Fd,
            Gd,
            Ft,
            Gt,
            ft,
            gt,
            t1;
        int x, y;

        depth = 1;
        n_top = 1 << logn_top;
        logn = logn_top - depth;
        n = 1 << logn;
        hn = n >> 1;

        /*
         * Equations are:
         *
         *   f' = f0^2 - X^2*f1^2
         *   g' = g0^2 - X^2*g1^2
         *   F' and G' are a solution to f'G' - g'F' = q (from deeper levels)
         *   F = F'*(g0 - X*g1)
         *   G = G'*(f0 - X*f1)
         *
         * f0, f1, g0, g1, f', g', F' and G' are all "compressed" to
         * degree N/2 (their odd-indexed coefficients are all zero).
         */

        /*
         * slen = size for our input f and g; also size of the reduced
         *        F and G we return (degree N)
         *
         * dlen = size of the F and G obtained from the deeper level
         *        (degree N/2)
         *
         * llen = size for intermediary F and G before reduction (degree N)
         *
         * We build our non-reduced F and G as two independent halves each,
         * of degree N/2 (F = F0 + X*F1, G = G0 + X*G1).
         */
        slen = MAX_BL_SMALL[depth];
        dlen = MAX_BL_SMALL[depth + 1];
        llen = MAX_BL_LARGE[depth];

        /*
         * Fd and Gd are the F and G from the deeper level. Ft and Gt
         * are the destination arrays for the unreduced F and G.
         */
        Fd = tp;
        Gd = Fd + dlen * hn;
        Ft = Gd + dlen * hn;
        Gt = Ft + llen * n;

        /*
         * We reduce Fd and Gd modulo all the small primes we will need,
         * and store the values in Ft and Gt.
         */
        for (u = 0; u < llen; u++)
        {
            int p, p0i, R2, Rx;
            int v;
            int xs, ys, xd, yd;

            p = FalconSmallPrime.PRIMES[u].p;
            p0i = FalconCommon.modp_ninv31(p);
            R2 = FalconCommon.modp_R2(p, p0i);
            Rx = FalconCommon.modp_Rx(dlen, p, p0i, R2);
            for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u;
                 v < hn;
                 v++, xs += dlen, ys += dlen, xd += llen, yd += llen)
            {
                tmp[xd] = FalconBigInt.mod_small_signed(xs, tmp, dlen, p, p0i, R2, Rx);
                tmp[yd] = FalconBigInt.mod_small_signed(ys, tmp, dlen, p, p0i, R2, Rx);
            }
        }

        /*
         * Now Fd and Gd are not needed anymore; we can squeeze them out.
         */
        // memmove(tmp, Ft, llen * n * sizeof(uint32_t));
        System.arraycopy(tmp, Ft, tmp, tp, llen * n);
        Ft = tp;
        // memmove(Ft + llen * n, Gt, llen * n * sizeof(uint32_t));
        System.arraycopy(tmp, Gt, tmp, Ft + llen * n, llen * n);
        Gt = Ft + llen * n;
        ft = Gt + llen * n;
        gt = ft + slen * n;

        t1 = gt + slen * n;

        /*
         * Compute our F and G modulo sufficiently many small primes.
         */
        for (u = 0; u < llen; u++)
        {
            int p, p0i, R2;
            int gm, igm, fx, gx, Fp, Gp;
            int e;
            int v;

            /*
             * All computations are done modulo p.
             */
            p = FalconSmallPrime.PRIMES[u].p;
            p0i = FalconCommon.modp_ninv31(p);
            R2 = FalconCommon.modp_R2(p, p0i);

            /*
             * We recompute things from the source f and g, of full
             * degree. However, we will need only the n first elements
             * of the inverse NTT table (igm); the call to modp_mkgm()
             * below will fill n_top elements in igm[] (thus overflowing
             * into fx[]) but later code will overwrite these extra
             * elements.
             */
            gm = t1;
            igm = gm + n_top;
            fx = igm + n;
            gx = fx + n_top;
            FalconCommon.modp_mkgm2(gm, igm, tmp, logn_top, FalconSmallPrime.PRIMES[u].g, p, p0i);

            /*
             * Set ft and gt to f and g modulo p, respectively.
             */
            for (v = 0; v < n_top; v++)
            {
                tmp[fx + v] = FalconCommon.modp_set(f.coeffs[v], p);
                tmp[gx + v] = FalconCommon.modp_set(g.coeffs[v], p);
            }

            /*
             * Convert to NTT and compute our f and g.
             */
            FalconNTT.modp_NTT2(fx, tmp, gm, tmp, logn_top, p, p0i);
            FalconNTT.modp_NTT2(gx, tmp, gm, tmp, logn_top, p, p0i);
            for (e = logn_top; e > logn; e--)
            {
                FalconCommon.modp_poly_rec_res(fx, tmp, e, p, p0i, R2);
                FalconCommon.modp_poly_rec_res(gx, tmp, e, p, p0i, R2);
            }

            /*
             * From that point onward, we only need tables for
             * degree n, so we can save some space.
             */
            if (depth > 0)
            { /* always true */
                // memmove(gm + n, igm, n * sizeof *igm);
                System.arraycopy(tmp, igm, tmp, gm + n, n);
                igm = gm + n;
                // memmove(igm + n, fx, n * sizeof *ft);
                System.arraycopy(tmp, fx, tmp, igm + n, n);
                fx = igm + n;
                // memmove(fx + n, gx, n * sizeof *gt);
                System.arraycopy(tmp, gx, tmp, fx + n, n);
                gx = fx + n;
            }

            /*
             * Get F' and G' modulo p and in NTT representation
             * (they have degree n/2). These values were computed
             * in a previous step, and stored in Ft and Gt.
             */
            Fp = gx + n;
            Gp = Fp + hn;
            for (v = 0, x = Ft + u, y = Gt + u;
                 v < hn; v++, x += llen, y += llen)
            {
                tmp[Fp + v] = tmp[x];
                tmp[Gp + v] = tmp[y];
            }
            FalconNTT.modp_NTT2(Fp, tmp, gm, tmp, logn - 1, p, p0i);
            FalconNTT.modp_NTT2(Gp, tmp, gm, tmp, logn - 1, p, p0i);

            /*
             * Compute our F and G modulo p.
             *
             * Equations are:
             *
             *   f'(x^2) = N(f)(x^2) = f * adj(f)
             *   g'(x^2) = N(g)(x^2) = g * adj(g)
             *
             *   f'*G' - g'*F' = q
             *
             *   F = F'(x^2) * adj(g)
             *   G = G'(x^2) * adj(f)
             *
             * The NTT representation of f is f(w) for all w which
             * are roots of phi. In the binary case, as well as in
             * the ternary case for all depth except the deepest,
             * these roots can be grouped in pairs (w,-w), and we
             * then have:
             *
             *   f(w) = adj(f)(-w)
             *   f(-w) = adj(f)(w)
             *
             * and w^2 is then a root for phi at the half-degree.
             *
             * At the deepest level in the ternary case, this still
             * holds, in the following sense: the roots of x^2-x+1
             * are (w,-w^2) (for w^3 = -1, and w != -1), and we
             * have:
             *
             *   f(w) = adj(f)(-w^2)
             *   f(-w^2) = adj(f)(w)
             *
             * In all case, we can thus compute F and G in NTT
             * representation by a few simple multiplications.
             * Moreover, the two roots for each pair are consecutive
             * in our bit-reversal encoding.
             */
            for (v = 0, x = Ft + u, y = Gt + u;
                 v < hn; v++, x += (llen << 1), y += (llen << 1))
            {
                int ftA, ftB, gtA, gtB;
                int mFp, mGp;

                ftA = tmp[fx + (v << 1) + 0];
                ftB = tmp[fx + (v << 1) + 1];
                gtA = tmp[gx + (v << 1) + 0];
                gtB = tmp[gx + (v << 1) + 1];
                mFp = FalconCommon.modp_montymul(tmp[Fp + v], R2, p, p0i);
                mGp = FalconCommon.modp_montymul(tmp[Gp + v], R2, p, p0i);
                tmp[x + 0] = FalconCommon.modp_montymul(gtB, mFp, p, p0i);
                tmp[x + llen] = FalconCommon.modp_montymul(gtA, mFp, p, p0i);
                tmp[y + 0] = FalconCommon.modp_montymul(ftB, mGp, p, p0i);
                tmp[y + llen] = FalconCommon.modp_montymul(ftA, mGp, p, p0i);
            }
            FalconNTT.modp_iNTT2_ext(Ft + u, tmp, llen, igm, tmp, logn, p, p0i);
            FalconNTT.modp_iNTT2_ext(Gt + u, tmp, llen, igm, tmp, logn, p, p0i);

            /*
             * Also save ft and gt (only up to size slen).
             */
            if (u < slen)
            {
                FalconNTT.modp_iNTT2(fx, tmp, igm, tmp, logn, p, p0i);
                FalconNTT.modp_iNTT2(gx, tmp, igm, tmp, logn, p, p0i);
                for (v = 0, x = ft + u, y = gt + u;
                     v < n; v++, x += slen, y += slen)
                {
                    tmp[x] = tmp[fx + v];
                    tmp[y] = tmp[gx + v];
                }
            }
        }

        /*
         * Rebuild f, g, F and G with the CRT. Note that the elements of F
         * and G are consecutive, and thus can be rebuilt in a single
         * loop; similarly, the elements of f and g are consecutive.
         */
        FalconBigInt.rebuild_CRT(Ft, tmp, llen, llen, n << 1, FalconSmallPrime.PRIMES, 1, t1, tmp);
        FalconBigInt.rebuild_CRT(ft, tmp, slen, slen, n << 1, FalconSmallPrime.PRIMES, 1, t1, tmp);

        /*
         * Here starts the Babai reduction, specialized for depth = 1.
         *
         * Candidates F and G (from Ft and Gt), and base f and g (ft and gt),
         * are converted to floating point. There is no scaling, and a
         * single pass is sufficient.
         */

        /*
         * Convert F and G into floating point (rt1 and rt2).
         */
        FalconFPR[]
            rt1 = new FalconFPR[n],
            rt2 = new FalconFPR[n];
        FalconFprPoly.poly_big_to_fp(rt1, Ft, tmp, llen, llen, logn);
        FalconFprPoly.poly_big_to_fp(rt2, Gt, tmp, llen, llen, logn);

        /*
         * Integer representation of F and G is no longer needed, we
         * can remove it.
         */
        // memmove(tmp, ft, 2 * slen * n * sizeof *ft);
        System.arraycopy(tmp, ft, tmp, tp, 2 * slen * n);
        ft = tp;
        gt = ft + slen * n;

        FalconFPR[]
            rt3 = new FalconFPR[n],
            rt4 = new FalconFPR[n];
        // memmove(rt3, rt1, 2 * n * sizeof *rt1);

        /*
         * Convert f and g into floating point (rt3 and rt4).
         */
        FalconFprPoly.poly_big_to_fp(rt3, ft, tmp, slen, slen, logn);
        FalconFprPoly.poly_big_to_fp(rt4, gt, tmp, slen, slen, logn);

        /*
         * Remove unneeded ft and gt.
         */
        // memmove(tmp, rt1, 4 * n * sizeof *rt1);
        // rt1 = (fpr *)tmp;
        // rt2 = rt1 + n;
        // rt3 = rt2 + n;
        // rt4 = rt3 + n;

        /*
         * We now have:
         *   rt1 = F
         *   rt2 = G
         *   rt3 = f
         *   rt4 = g
         * in that order in RAM. We convert all of them to FFT.
         */
        FalconFFT.fft(0, rt1, logn);
        FalconFFT.fft(0, rt2, logn);
        FalconFFT.fft(0, rt3, logn);
        FalconFFT.fft(0, rt4, logn);

        /*
         * Compute:
         *   rt5 = F*adj(f) + G*adj(g)
         *   rt6 = 1 / (f*adj(f) + g*adj(g))
         * (Note that rt6 is half-length.)
         */
        FalconFPR[]
            rt5 = new FalconFPR[n],
            rt6 = new FalconFPR[n >> 1];
        FalconFFT.poly_add_muladj_fft(0, rt5, 0, rt1, 0, rt2, 0, rt3, 0, rt4, logn);
        FalconFFT.poly_invnorm2_fft(0, rt6, 0, rt3, 0, rt4, logn);

        /*
         * Compute:
         *   rt5 = (F*adj(f)+G*adj(g)) / (f*adj(f)+g*adj(g))
         */
        FalconFFT.poly_mul_autoadj_fft(0, rt5, 0, rt6, logn);

        /*
         * Compute k as the rounded version of rt5. Check that none of
         * the values is larger than 2^63-1 (in absolute value)
         * because that would make the fpr_rint() do something undefined;
         * note that any out-of-bounds value here implies a failure and
         * (f,g) will be discarded, so we can make a simple test.
         */
        FalconFFT.ifft(0, rt5, logn);
        for (u = 0; u < n; u++)
        {
            FalconFPR z;

            z = rt5[u];
            if (!z.lt(FalconFPR.fpr_ptwo63m1) || !FalconFPR.fpr_mtwo63m1.lt(z))
            {
                return false;
            }
            rt5[u] = FalconFPR.fpr_of(z.rint());
        }
        FalconFFT.fft(0, rt5, logn);

        /*
         * Subtract k*f from F, and k*g from G.
         */
        FalconFFT.poly_mul_fft(0, rt3, 0, rt5, logn);
        FalconFFT.poly_mul_fft(0, rt4, 0, rt5, logn);
        FalconFFT.poly_sub(0, rt1, 0, rt3, logn);
        FalconFFT.poly_sub(0, rt2, 0, rt4, logn);
        FalconFFT.ifft(0, rt1, logn);
        FalconFFT.ifft(0, rt2, logn);

        /*
         * Convert back F and G to integers, and return.
         */
        Ft = tp;
        Gt = Ft + n;
        // rt3 = align_fpr(tmp, Gt + n);
        // memmove(rt3, rt1, 2 * n * sizeof *rt1);
        // rt1 = rt3;
        // rt2 = rt1 + n;
        for (u = 0; u < n; u++)
        {
            tmp[Ft + u] = (int)rt1[u].rint();
            tmp[Gt + u] = (int)rt2[u].rint();
        }

        return true;
    }

    boolean solve_NTRU_intermediate(int logn_top, FalconSmallPoly f, FalconSmallPoly g, int depth, int tp, int[] tmp)
    {
        /*
         * In this function, 'logn' is the log2 of the degree for
         * this step. If N = 2^logn, then:
         *  - the F and G values already in fk->tmp (from the deeper
         *    levels) have degree N/2;
         *  - this function should return F and G of degree N.
         */
//        System.out.println(String.format("  Starting NTRU Solve depth %d...",depth));
        int logn;
        int n, hn, slen, dlen, llen, rlen, FGlen, u;
        int Fd, // tmp
            Gd, // tmp
            Ft, // tmp
            Gt, // tmp
            ft, // tmp
            gt, // tmp
            t1; // tmp
        int scale_fg, minbl_fg, maxbl_fg, maxbl_FG, scale_k;
        int x, y;
        FalconSmallPrime[] primes;

        logn = logn_top - depth;
        n = 1 << logn;
        hn = n >> 1;

        /*
         * slen = size for our input f and g; also size of the reduced
         *        F and G we return (degree N)
         *
         * dlen = size of the F and G obtained from the deeper level
         *        (degree N/2 or N/3)
         *
         * llen = size for intermediary F and G before reduction (degree N)
         *
         * We build our non-reduced F and G as two independent halves each,
         * of degree N/2 (F = F0 + X*F1, G = G0 + X*G1).
         */
        slen = MAX_BL_SMALL[depth];
        dlen = MAX_BL_SMALL[depth + 1];
        llen = MAX_BL_LARGE[depth];
        primes = FalconSmallPrime.PRIMES;

        /*
         * Fd and Gd are the F and G from the deeper level.
         */
        Fd = tp;
        Gd = Fd + dlen * hn;

        /*
         * Compute the input f and g for this level. Note that we get f
         * and g in RNS + NTT representation.
         */
        ft = Gd + dlen * hn;
        make_fg(ft, tmp, f, g, logn_top, depth, true);

        /*
         * Move the newly computed f and g to make room for our candidate
         * F and G (unreduced).
         */
        Ft = tp;
        Gt = Ft + n * llen;
        t1 = Gt + n * llen;
        // memmove(t1, ft, 2 * n * slen * sizeof *ft);
        System.arraycopy(tmp, ft, tmp, t1, 2 * n * slen);
        ft = t1;
        gt = ft + slen * n;
        t1 = gt + slen * n;

        /*
         * Move Fd and Gd _after_ f and g.
         */
        // memmove(t1, Fd, 2 * hn * dlen * sizeof *Fd);
        System.arraycopy(tmp, Fd, tmp, t1, 2 * hn * dlen);
        Fd = t1;
        Gd = Fd + hn * dlen;

        /*
         * We reduce Fd and Gd modulo all the small primes we will need,
         * and store the values in Ft and Gt (only n/2 values in each).
         */
        for (u = 0; u < llen; u++)
        {
            int p, p0i, R2, Rx;
            int v;
            int xs, ys, xd, yd;

            p = primes[u].p;
            p0i = FalconCommon.modp_ninv31(p);
            R2 = FalconCommon.modp_R2(p, p0i);
            Rx = FalconCommon.modp_Rx(dlen, p, p0i, R2);
            for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u;
                 v < hn;
                 v++, xs += dlen, ys += dlen, xd += llen, yd += llen)
            {
                tmp[xd] = FalconBigInt.mod_small_signed(xs, tmp, dlen, p, p0i, R2, Rx);
                tmp[yd] = FalconBigInt.mod_small_signed(ys, tmp, dlen, p, p0i, R2, Rx);
            }
        }

        /*
         * We do not need Fd and Gd after that point.
         */

        /*
         * Compute our F and G modulo sufficiently many small primes.
         */
        for (u = 0; u < llen; u++)
        {
            int p, p0i, R2;
            int gm, igm, fx, gx, Fp, Gp;
            int v;

            /*
             * All computations are done modulo p.
             */
            p = primes[u].p;
            p0i = FalconCommon.modp_ninv31(p);
            R2 = FalconCommon.modp_R2(p, p0i);

            /*
             * If we processed slen words, then f and g have been
             * de-NTTized, and are in RNS; we can rebuild them.
             */
            if (u == slen)
            {
                FalconBigInt.rebuild_CRT(ft, tmp, slen, slen, n, primes, 1, t1, tmp);
                FalconBigInt.rebuild_CRT(gt, tmp, slen, slen, n, primes, 1, t1, tmp);
            }

            gm = t1;
            igm = gm + n;
            fx = igm + n;
            gx = fx + n;

            FalconCommon.modp_mkgm2(gm, igm, tmp, logn, primes[u].g, p, p0i);

            if (u < slen)
            {
                for (v = 0, x = ft + u, y = gt + u;
                     v < n; v++, x += slen, y += slen)
                {
                    tmp[fx + v] = tmp[x];
                    tmp[gx + v] = tmp[y];
                }
                FalconNTT.modp_iNTT2_ext(ft + u, tmp, slen, igm, tmp, logn, p, p0i);
                FalconNTT.modp_iNTT2_ext(gt + u, tmp, slen, igm, tmp, logn, p, p0i);
            }
            else
            {
                int Rx;

                Rx = FalconCommon.modp_Rx(slen, p, p0i, R2);
                for (v = 0, x = ft, y = gt;
                     v < n; v++, x += slen, y += slen)
                {
                    tmp[fx + v] = FalconBigInt.mod_small_signed(x, tmp, slen,
                        p, p0i, R2, Rx);
                    tmp[gx + v] = FalconBigInt.mod_small_signed(y, tmp, slen,
                        p, p0i, R2, Rx);
                }
                FalconNTT.modp_NTT2(fx, tmp, gm, tmp, logn, p, p0i);
                FalconNTT.modp_NTT2(gx, tmp, gm, tmp, logn, p, p0i);
            }

            /*
             * Get F' and G' modulo p and in NTT representation
             * (they have degree n/2). These values were computed in
             * a previous step, and stored in Ft and Gt.
             */
            Fp = gx + n;
            Gp = Fp + hn;
            for (v = 0, x = Ft + u, y = Gt + u;
                 v < hn; v++, x += llen, y += llen)
            {
                tmp[Fp + v] = tmp[x];
                tmp[Gp + v] = tmp[y];
            }
            FalconNTT.modp_NTT2(Fp, tmp, gm, tmp, logn - 1, p, p0i);
            FalconNTT.modp_NTT2(Gp, tmp, gm, tmp, logn - 1, p, p0i);

            /*
             * Compute our F and G modulo p.
             *
             * General case:
             *
             *   we divide degree by d = 2 or 3
             *   f'(x^d) = N(f)(x^d) = f * adj(f)
             *   g'(x^d) = N(g)(x^d) = g * adj(g)
             *   f'*G' - g'*F' = q
             *   F = F'(x^d) * adj(g)
             *   G = G'(x^d) * adj(f)
             *
             * We compute things in the NTT. We group roots of phi
             * such that all roots x in a group share the same x^d.
             * If the roots in a group are x_1, x_2... x_d, then:
             *
             *   N(f)(x_1^d) = f(x_1)*f(x_2)*...*f(x_d)
             *
             * Thus, we have:
             *
             *   G(x_1) = f(x_2)*f(x_3)*...*f(x_d)*G'(x_1^d)
             *   G(x_2) = f(x_1)*f(x_3)*...*f(x_d)*G'(x_1^d)
             *   ...
             *   G(x_d) = f(x_1)*f(x_2)*...*f(x_{d-1})*G'(x_1^d)
             *
             * In all cases, we can thus compute F and G in NTT
             * representation by a few simple multiplications.
             * Moreover, in our chosen NTT representation, roots
             * from the same group are consecutive in RAM.
             */
            for (v = 0, x = Ft + u, y = Gt + u; v < hn;
                 v++, x += (llen << 1), y += (llen << 1))
            {
                int ftA, ftB, gtA, gtB;
                int mFp, mGp;

                ftA = tmp[fx + (v << 1) + 0];
                ftB = tmp[fx + (v << 1) + 1];
                gtA = tmp[gx + (v << 1) + 0];
                gtB = tmp[gx + (v << 1) + 1];
                mFp = FalconCommon.modp_montymul(tmp[Fp + v], R2, p, p0i);
                mGp = FalconCommon.modp_montymul(tmp[Gp + v], R2, p, p0i);
                tmp[x + 0] = FalconCommon.modp_montymul(gtB, mFp, p, p0i);
                tmp[x + llen] = FalconCommon.modp_montymul(gtA, mFp, p, p0i);
                tmp[y + 0] = FalconCommon.modp_montymul(ftB, mGp, p, p0i);
                tmp[y + llen] = FalconCommon.modp_montymul(ftA, mGp, p, p0i);
            }
            FalconNTT.modp_iNTT2_ext(Ft + u, tmp, llen, igm, tmp, logn, p, p0i);
            FalconNTT.modp_iNTT2_ext(Gt + u, tmp, llen, igm, tmp, logn, p, p0i);
        }

        /*
         * Rebuild F and G with the CRT.
         */
        FalconBigInt.rebuild_CRT(Ft, tmp, llen, llen, n, primes, 1, t1, tmp);
        FalconBigInt.rebuild_CRT(Gt, tmp, llen, llen, n, primes, 1, t1, tmp);

        /*
         * At that point, Ft, Gt, ft and gt are consecutive in RAM (in that
         * order).
         */

        /*
         * Apply Babai reduction to bring back F and G to size slen.
         *
         * We use the FFT to compute successive approximations of the
         * reduction coefficient. We first isolate the top bits of
         * the coefficients of f and g, and convert them to floating
         * point; with the FFT, we compute adj(f), adj(g), and
         * 1/(f*adj(f)+g*adj(g)).
         *
         * Then, we repeatedly apply the following:
         *
         *   - Get the top bits of the coefficients of F and G into
         *     floating point, and use the FFT to compute:
         *        (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g))
         *
         *   - Convert back that value into normal representation, and
         *     round it to the nearest integers, yielding a polynomial k.
         *     Proper scaling is applied to f, g, F and G so that the
         *     coefficients fit on 32 bits (signed).
         *
         *   - Subtract k*f from F and k*g from G.
         *
         * Under normal conditions, this process reduces the size of F
         * and G by some bits at each iteration. For constant-time
         * operation, we do not want to measure the actual length of
         * F and G; instead, we do the following:
         *
         *   - f and g are converted to floating-point, with some scaling
         *     if necessary to keep values in the representable range.
         *
         *   - For each iteration, we _assume_ a maximum size for F and G,
         *     and use the values at that size. If we overreach, then
         *     we get zeros, which is harmless: the resulting coefficients
         *     of k will be 0 and the value won't be reduced.
         *
         *   - We conservatively assume that F and G will be reduced by
         *     at least 25 bits at each iteration.
         *
         * Even when reaching the bottom of the reduction, reduction
         * coefficient will remain low. If it goes out-of-range, then
         * something wrong occurred and the whole NTRU solving fails.
         */

        /*
         * Memory layout:
         *  - We need to compute and keep adj(f), adj(g), and
         *    1/(f*adj(f)+g*adj(g)) (sizes N, N and N/2 fp numbers,
         *    respectively).
         *  - At each iteration we need two extra fp buffer (N fp values),
         *    and produce a k (N 32-bit words). k will be shared with one
         *    of the fp buffers.
         *  - To compute k*f and k*g efficiently (with the NTT), we need
         *    some extra room; we reuse the space of the temporary buffers.
         *
         * Arrays of 'fpr' are obtained from the temporary array itself.
         * We ensure that the base is at a properly aligned offset (the
         * source array tmp[] is supposed to be already aligned).
         */
        FalconFPR[]
            rt1 = new FalconFPR[n],
            rt2 = new FalconFPR[n],
            rt3 = new FalconFPR[n],
            rt4 = new FalconFPR[n],
            rt5 = new FalconFPR[n >> 1];
        int[]
            k = new int[n];

        /*
         * Get f and g into rt3 and rt4 as floating-point approximations.
         *
         * We need to "scale down" the floating-point representation of
         * coefficients when they are too big. We want to keep the value
         * below 2^310 or so. Thus, when values are larger than 10 words,
         * we consider only the top 10 words. Array lengths have been
         * computed so that average maximum length will fall in the
         * middle or the upper half of these top 10 words.
         */
        rlen = (slen > 10) ? 10 : slen;
        FalconFprPoly.poly_big_to_fp(rt3, ft + slen - rlen, tmp, rlen, slen, logn);
        FalconFprPoly.poly_big_to_fp(rt4, gt + slen - rlen, tmp, rlen, slen, logn);

        /*
         * Values in rt3 and rt4 are downscaled by 2^(scale_fg).
         */
        scale_fg = 31 * (int)(slen - rlen);

        /*
         * Estimated boundaries for the maximum size (in bits) of the
         * coefficients of (f,g). We use the measured average, and
         * allow for a deviation of at most six times the standard
         * deviation.
         */
        minbl_fg = FalconBitlen.BITLENGTH[depth].avg - 6 * FalconBitlen.BITLENGTH[depth].std;
        maxbl_fg = FalconBitlen.BITLENGTH[depth].avg + 6 * FalconBitlen.BITLENGTH[depth].std;

        /*
         * Compute 1/(f*adj(f)+g*adj(g)) in rt5. We also keep adj(f)
         * and adj(g) in rt3 and rt4, respectively.
         */
        FalconFFT.fft(0, rt3, logn);
        FalconFFT.fft(0, rt4, logn);
        FalconFFT.poly_invnorm2_fft(0, rt5, 0, rt3, 0, rt4, logn);
        FalconFFT.poly_adj_fft(0, rt3, logn);
        FalconFFT.poly_adj_fft(0, rt4, logn);

        /*
         * Reduce F and G repeatedly.
         *
         * The expected maximum bit length of coefficients of F and G
         * is kept in maxbl_FG, with the corresponding word length in
         * FGlen.
         */
        FGlen = llen;
        maxbl_FG = 31 * (int)llen;

        /*
         * Each reduction operation computes the reduction polynomial
         * "k". We need that polynomial to have coefficients that fit
         * on 32-bit signed integers, with some scaling; thus, we use
         * a descending sequence of scaling values, down to zero.
         *
         * The size of the coefficients of k is (roughly) the difference
         * between the size of the coefficients of (F,G) and the size
         * of the coefficients of (f,g). Thus, the maximum size of the
         * coefficients of k is, at the start, maxbl_FG - minbl_fg;
         * this is our starting scale value for k.
         *
         * We need to estimate the size of (F,G) during the execution of
         * the algorithm; we are allowed some overestimation but not too
         * much (poly_big_to_fp() uses a 310-bit window). Generally
         * speaking, after applying a reduction with k scaled to
         * scale_k, the size of (F,G) will be size(f,g) + scale_k + dd,
         * where 'dd' is a few bits to account for the fact that the
         * reduction is never perfect (intuitively, dd is on the order
         * of sqrt(N), so at most 5 bits; we here allow for 10 extra
         * bits).
         *
         * The size of (f,g) is not known exactly, but maxbl_fg is an
         * upper bound.
         */
        scale_k = maxbl_FG - minbl_fg;

        for (; ; )
        {
            int scale_FG, dc, new_maxbl_FG;
            int scl, sch;
            FalconFPR pdc, pt;

            /*
             * Convert current F and G into floating-point. We apply
             * scaling if the current length is more than 10 words.
             */
            rlen = (FGlen > 10) ? 10 : FGlen;
            scale_FG = 31 * (int)(FGlen - rlen);
            FalconFprPoly.poly_big_to_fp(rt1, Ft + FGlen - rlen, tmp, rlen, llen, logn);
            FalconFprPoly.poly_big_to_fp(rt2, Gt + FGlen - rlen, tmp, rlen, llen, logn);

            /*
             * Compute (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g)) in rt2.
             */
            FalconFFT.fft(0, rt1, logn);
            FalconFFT.fft(0, rt2, logn);
            FalconFFT.poly_mul_fft(0, rt1, 0, rt3, logn);
            FalconFFT.poly_mul_fft(0, rt2, 0, rt4, logn);
            FalconFFT.poly_add(0, rt2, 0, rt1, logn);
            FalconFFT.poly_mul_autoadj_fft(0, rt2, 0, rt5, logn);
            FalconFFT.ifft(0, rt2, logn);

            /*
             * (f,g) are scaled by 'scale_fg', meaning that the
             * numbers in rt3/rt4 should be multiplied by 2^(scale_fg)
             * to have their true mathematical value.
             *
             * (F,G) are similarly scaled by 'scale_FG'. Therefore,
             * the value we computed in rt2 is scaled by
             * 'scale_FG-scale_fg'.
             *
             * We want that value to be scaled by 'scale_k', hence we
             * apply a corrective scaling. After scaling, the values
             * should fit in -2^31-1..+2^31-1.
             */
            dc = scale_k - scale_FG + scale_fg;

            /*
             * We will need to multiply values by 2^(-dc). The value
             * 'dc' is not secret, so we can compute 2^(-dc) with a
             * non-constant-time process.
             * (We could use ldexp(), but we prefer to avoid any
             * dependency on libm. When using FP emulation, we could
             * use our fpr_ldexp(), which is constant-time.)
             */
            if (dc < 0)
            {
                dc = -dc;
                pt = FalconFPR.fpr_two;
            }
            else
            {
                pt = FalconFPR.fpr_onehalf;
            }
            pdc = FalconFPR.fpr_one;
            while (dc != 0)
            {
                if ((dc & 1) != 0)
                {
                    pdc = pdc.mul(pt);
                }
                dc >>= 1;
                pt = pt.sqr();
            }

            for (u = 0; u < n; u++)
            {
                FalconFPR xv;

                xv = rt2[u].mul(pdc);

                /*
                 * Sometimes the values can be out-of-bounds if
                 * the algorithm fails; we must not call
                 * fpr_rint() (and cast to int32_t) if the value
                 * is not in-bounds. Note that the test does not
                 * break constant-time discipline, since any
                 * failure here implies that we discard the current
                 * secret key (f,g).
                 */
                if (!FalconFPR.fpr_mtwo31m1.lt(xv)
                    || !xv.lt(FalconFPR.fpr_ptwo31m1))
                {
                    return false;
                }
                k[u] = (int)xv.rint();
            }

            /*
             * Values in k[] are integers. They really are scaled
             * down by maxbl_FG - minbl_fg bits.
             *
             * If we are at low depth, then we use the NTT to
             * compute k*f and k*g.
             */
            sch = (int)(scale_k / 31);
            scl = (int)(scale_k % 31);
            if (depth <= DEPTH_INT_FG)
            {
                FalconNTT.poly_sub_scaled_ntt(Ft, tmp, FGlen, llen, ft, tmp, slen, slen,
                    0, k, sch, scl, logn, t1, tmp);
                FalconNTT.poly_sub_scaled_ntt(Gt, tmp, FGlen, llen, gt, tmp, slen, slen,
                    0, k, sch, scl, logn, t1, tmp);
            }
            else
            {
                poly_sub_scaled(Ft, tmp, FGlen, llen, ft, tmp, slen, slen,
                    0, k, sch, scl, logn);
                poly_sub_scaled(Gt, tmp, FGlen, llen, gt, tmp, slen, slen,
                    0, k, sch, scl, logn);
            }

            /*
             * We compute the new maximum size of (F,G), assuming that
             * (f,g) has _maximal_ length (i.e. that reduction is
             * "late" instead of "early". We also adjust FGlen
             * accordingly.
             */
            new_maxbl_FG = scale_k + maxbl_fg + 10;
            if (new_maxbl_FG < maxbl_FG)
            {
                maxbl_FG = new_maxbl_FG;
                if ((int)FGlen * 31 >= maxbl_FG + 31)
                {
                    FGlen--;
                }
            }

            /*
             * We suppose that scaling down achieves a reduction by
             * at least 25 bits per iteration. We stop when we have
             * done the loop with an unscaled k.
             */
            if (scale_k <= 0)
            {
                break;
            }
            scale_k -= 25;
            if (scale_k < 0)
            {
                scale_k = 0;
            }
        }

        /*
         * If (F,G) length was lowered below 'slen', then we must take
         * care to re-extend the sign.
         */
        if (FGlen < slen)
        {
            for (u = 0; u < n; u++, Ft += llen, Gt += llen)
            {
                int v;
                int sw;

                sw = -(tmp[Ft + FGlen - 1] >>> 30) >>> 1;
                for (v = FGlen; v < slen; v++)
                {
                    tmp[Ft + v] = sw;
                }
                sw = -(tmp[Gt + FGlen - 1] >>> 30) >>> 1;
                for (v = FGlen; v < slen; v++)
                {
                    tmp[Gt + v] = sw;
                }
            }
        }

        /*
         * Compress encoding of all values to 'slen' words (this is the
         * expected output format).
         */
        for (u = 0, x = tp, y = tp;
             u < (n << 1); u++, x += slen, y += llen)
        {
            // memmove(x, y, slen * sizeof *y);
            System.arraycopy(tmp, y, tmp, x, slen);
        }
//        System.out.println(String.format("  Finished depth %d",depth));
        return true;
    }

    private void poly_sub_scaled(int F, int[] Fdata, int Flen, int Fstride, int f, int[] fdata, int flen, int fstride,
                                 int k, int[] kdata, int sch, int scl, int logn)
    {
        int n, u;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            int kf;
            int v;
            int x;
            int y;

            kf = -kdata[k + u];
            x = F + u * Fstride;
            y = f;
            for (v = 0; v < n; v++)
            {
                FalconBigInt.add_scaled_mul_small(x, Fdata, Flen, y, fdata, flen, kf, sch, scl);
                if (u + v == n - 1)
                {
                    x = F;
                    kf = -kf;
                }
                else
                {
                    x += Fstride;
                }
                y += fstride;
            }
        }
    }

    private boolean solve_NTRU_deepest(int logn_top, FalconSmallPoly f, FalconSmallPoly g,
                                       int tp, int[] tmp)
    {
        int len;
        FalconSmallPrime[] primes;
        len = MAX_BL_SMALL[logn_top];
        primes = FalconSmallPrime.PRIMES;
        int
            Fp = tp,
            Gp = Fp + len,
            fp = Gp + len,
            gp = fp + len,
            t1 = gp + len,
            q;
//        System.out.println("  Starting NTRU Solve deepest...");
        make_fg(fp, tmp, f, g, logn_top, logn_top, false);

        /*
         * We use the CRT to rebuild the resultants as big integers.
         * There are two such big integers. The resultants are always
         * nonnegative.
         */
        FalconBigInt.rebuild_CRT(fp, tmp, len, len, 2, primes, 0, t1, tmp);

        /*
         * Apply the binary GCD. The zint_bezout() function works only
         * if both inputs are odd.
         *
         * We can test on the result and return 0 because that would
         * imply failure of the NTRU solving equation, and the (f,g)
         * values will be abandoned in that case.
         */
        if (!FalconBigInt.bezout(Gp, tmp, Fp, tmp, fp, tmp, gp, tmp, len, t1, tmp))
        {
//            System.out.println("  Aborted - bezout");
            return false;
        }

        /*
         * Multiply the two values by the target value q. Values must
         * fit in the destination arrays.
         * We can again test on the returned words: a non-zero output
         * of zint_mul_small() means that we exceeded our array
         * capacity, and that implies failure and rejection of (f,g).
         */
        q = 12289;
        if (FalconBigInt.mul_small(Fp, tmp, len, q) != 0
            || FalconBigInt.mul_small(Gp, tmp, len, q) != 0)
        {
//            System.out.println("  Aborted - mul_small");
            return false;
        }
//        System.out.println("  Done");

        return true;
    }

    /*
     * Compute f and g at a specific depth, in RNS notation.
     *
     * Returned values are stored in the data[] array, at slen words per integer.
     *
     * Conditions:
     *   0 <= depth <= logn
     *
     * Space use in data[]: enough room for any two successive values (f', g',
     * f and g).
     */
    private void make_fg(int dp, int[] data, FalconSmallPoly f, FalconSmallPoly g, int logn, int depth, boolean out_ntt)
    {
        int n, u;
        n = 1 << logn;
        int d, p0;
        FalconSmallPrime[] primes;
        int // bounded to data
            ft = dp,
            gt = ft + n;
        primes = FalconSmallPrime.PRIMES;
        p0 = primes[0].p;
        for (u = 0; u < n; u++)
        {
            data[ft + u] = FalconCommon.modp_set(f.coeffs[u], p0);
            data[gt + u] = FalconCommon.modp_set(g.coeffs[u], p0);
        }
        if (depth == 0 && out_ntt)
        {
            int // bounded to data
                gm = gt + n,
                igm = gm + n;
            int p, p0i;

            p = primes[0].p;
            p0i = FalconCommon.modp_ninv31(p);
            FalconCommon.modp_mkgm2(gm, igm, data, logn, primes[0].g, p, p0i);
            FalconNTT.modp_NTT2(ft, data, gm, data, logn, p, p0i);
            FalconNTT.modp_NTT2(gt, data, gm, data, logn, p, p0i);
            return;
        }
        for (d = 0; d < depth; d++)
        {
            make_fg_step(dp, data, logn - d, d,
                d != 0, (d + 1) < depth || out_ntt);
        }
    }

    private void make_fg_step(int dp, int[] data, int logn, int depth, boolean in_ntt, boolean out_ntt)
    {
        int n, hn, u;
        n = 1 << logn;
        hn = n >> 1;
        int slen, tlen;
        FalconSmallPrime[] primes = FalconSmallPrime.PRIMES;
        slen = MAX_BL_SMALL[depth];
        tlen = MAX_BL_SMALL[depth + 1];
        int
            fd = dp,
            gd = fd + hn * tlen,
            fs = gd + hn * tlen,
            gs = fs + n * slen,
            gm = gs + n * slen,
            igm = gm + n,
            t1 = igm + n;
        System.arraycopy(data, dp, data, fs, 2 * n * slen);
        /*
         * First slen words: we use the input values directly, and apply
         * inverse NTT as we go.
         */
        for (u = 0; u < slen; u++)
        {
            int p, p0i, R2;
            int v;
            int x;

            p = primes[u].p;
            p0i = FalconCommon.modp_ninv31(p);
            R2 = FalconCommon.modp_R2(p, p0i);
            FalconCommon.modp_mkgm2(gm, igm, data, logn, primes[u].g, p, p0i);

            for (v = 0, x = fs + u; v < n; v++, x += slen)
            {
                data[t1 + v] = data[x];
            }
            if (!in_ntt)
            {
                FalconNTT.modp_NTT2(t1, data, gm, data, logn, p, p0i);
            }
            for (v = 0, x = fd + u; v < hn; v++, x += tlen)
            {
                int w0, w1;

                w0 = data[t1 + (v << 1) + 0];
                w1 = data[t1 + (v << 1) + 1];
                data[x] = FalconCommon.modp_montymul(
                    FalconCommon.modp_montymul(w0, w1, p, p0i), R2, p, p0i);
            }
            if (in_ntt)
            {
                FalconNTT.modp_iNTT2_ext(fs + u, data, slen, igm, data, logn, p, p0i);
            }

            for (v = 0, x = gs + u; v < n; v++, x += slen)
            {
                data[t1 + v] = data[x];
            }
            if (!in_ntt)
            {
                FalconNTT.modp_NTT2(t1, data, gm, data, logn, p, p0i);
            }
            for (v = 0, x = gd + u; v < hn; v++, x += tlen)
            {
                int w0, w1;

                w0 = data[t1 + (v << 1) + 0];
                w1 = data[t1 + (v << 1) + 1];
                data[x] = FalconCommon.modp_montymul(
                    FalconCommon.modp_montymul(w0, w1, p, p0i), R2, p, p0i);
            }
            if (in_ntt)
            {
                FalconNTT.modp_iNTT2_ext(gs + u, data, slen, igm, data, logn, p, p0i);
            }

            if (!out_ntt)
            {
                FalconNTT.modp_iNTT2_ext(fd + u, data, tlen, igm, data, logn - 1, p, p0i);
                FalconNTT.modp_iNTT2_ext(gd + u, data, tlen, igm, data, logn - 1, p, p0i);
            }
        }
        /*
         * Since the fs and gs words have been de-NTTized, we can use the
         * CRT to rebuild the values.
         */
        FalconBigInt.rebuild_CRT(fs, data, slen, slen, n, primes, 1, gm, data);
        FalconBigInt.rebuild_CRT(gs, data, slen, slen, n, primes, 1, gm, data);

        /*
         * Remaining words: use modular reductions to extract the values.
         */
        for (u = slen; u < tlen; u++)
        {
            int p, p0i, R2, Rx;
            int v;
            int x;

            p = primes[u].p;
            p0i = FalconCommon.modp_ninv31(p);
            R2 = FalconCommon.modp_R2(p, p0i);
            Rx = FalconCommon.modp_Rx(slen, p, p0i, R2);
            FalconCommon.modp_mkgm2(gm, igm, data, logn, primes[u].g, p, p0i);
            for (v = 0, x = fs; v < n; v++, x += slen)
            {
                data[t1 + v] = FalconBigInt.mod_small_signed(x, data, slen, p, p0i, R2, Rx);
            }
            FalconNTT.modp_NTT2(t1, data, gm, data, logn, p, p0i);
            for (v = 0, x = fd + u; v < hn; v++, x += tlen)
            {
                int w0, w1;

                w0 = data[t1 + (v << 1) + 0];
                w1 = data[t1 + (v << 1) + 1];
                data[x] = FalconCommon.modp_montymul(
                    FalconCommon.modp_montymul(w0, w1, p, p0i), R2, p, p0i);
            }
            for (v = 0, x = gs; v < n; v++, x += slen)
            {
                data[t1 + v] = FalconBigInt.mod_small_signed(x, data, slen, p, p0i, R2, Rx);
            }
            FalconNTT.modp_NTT2(t1, data, gm, data, logn, p, p0i);
            for (v = 0, x = gd + u; v < hn; v++, x += tlen)
            {
                int w0, w1;

                w0 = data[t1 + (v << 1) + 0];
                w1 = data[t1 + (v << 1) + 1];
                data[x] = FalconCommon.modp_montymul(
                    FalconCommon.modp_montymul(w0, w1, p, p0i), R2, p, p0i);
            }

            if (!out_ntt)
            {
                FalconNTT.modp_iNTT2_ext(fd + u, data, tlen, igm, data, logn - 1, p, p0i);
                FalconNTT.modp_iNTT2_ext(gd + u, data, tlen, igm, data, logn - 1, p, p0i);
            }
        }
    }
}
