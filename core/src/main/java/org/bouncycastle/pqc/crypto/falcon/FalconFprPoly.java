package org.bouncycastle.pqc.crypto.falcon;

class FalconFprPoly
{
    FalconFPR[] coeffs;

    FalconFprPoly(int n)
    {
        this.coeffs = new FalconFPR[n];
    }

    FalconFprPoly(FalconFPR[] coeffs)
    {
        this.coeffs = coeffs.clone();
    }

    FalconFprPoly(FalconBigPoly f, int flen, int fstride, int logn)
    {
        int n, u;
        n = 1 << logn;
        this.coeffs = new FalconFPR[n];
        if (flen == 0)
        {
            for (u = 0; u < n; u++)
            {
                this.coeffs[u] = FalconFPR.fpr_zero;
            }
            return;
        }
        for (u = 0; u < n; u++)
        {
            int v;
            int neg, cc, xm;
            FalconFPR x, fsc;
            FalconBigInt fn;
            fn = f.coeffs[u];

            neg = -(fn.num[flen - 1] >>> 30);
            xm = neg >>> 1;
            cc = neg & 1;
            x = FalconFPR.fpr_zero;
            fsc = FalconFPR.fpr_one;
            for (v = 0; v < flen; v++, fsc = fsc.mul(FalconFPR.fpr_ptwo31))
            {
                int w;
                w = (fn.num[v] ^ xm) + cc;
                cc = w >>> 31;
                w &= 0x7FFFFFFF;
                w -= (w << 1) & neg;
                x = x.add(FalconFPR.fpr_of(w).mul(fsc));
            }
            this.coeffs[u] = x;
        }
    }

    FalconFprPoly(FalconSmallPoly f, int logn)
    {
        int n, u;
        n = 1 << logn;
        this.coeffs = new FalconFPR[n];
        for (u = 0; u < n; u++)
        {
            this.coeffs[u] = FalconFPR.fpr_of(f.coeffs[u]);
        }
    }

    static void poly_big_to_fp(FalconFPR[] d, int fp, int[] fdata, int flen, int fstride, int logn)
    {
        int n, u;
        int f = fp;

        n = 1 << logn;
        if (flen == 0)
        {
            for (u = 0; u < n; u++)
            {
                d[u] = FalconFPR.fpr_zero;
            }
            return;
        }
        for (u = 0; u < n; u++, f += fstride)
        {
            int v;
            int neg, cc, xm;
            FalconFPR x, fsc;

            /*
             * Get sign of the integer; if it is negative, then we
             * will load its absolute value instead, and negate the
             * result.
             */
            neg = -(fdata[f + flen - 1] >>> 30);
            xm = neg >>> 1;
            cc = neg & 1;
            x = FalconFPR.fpr_zero;
            fsc = FalconFPR.fpr_one;
            for (v = 0; v < flen; v++, fsc = fsc.mul(FalconFPR.fpr_ptwo31))
            {
                int w;

                w = (fdata[f + v] ^ xm) + cc;
                cc = w >>> 31;
                w &= 0x7FFFFFFF;
                w -= (w << 1) & neg;
                x = x.add(FalconFPR.fpr_of(w).mul(fsc));
            }
            d[u] = x;
        }
    }
}
