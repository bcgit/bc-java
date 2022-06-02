package org.bouncycastle.pqc.crypto.falcon;

class FalconShortPoly
{
    short[] coeffs;

    FalconShortPoly(int n)
    {
        this.coeffs = new short[n];
    }

    FalconShortPoly(short[] f)
    {
        this.coeffs = f.clone();
    }

    /*
     * computes the public key from f and g and puts it in out
     * requires out to be initialised with 1 << logn spaces (2^logn)
     * returns true on sucess, false on failure
     */
    static boolean compute_public(FalconShortPoly out, FalconSmallPoly f, FalconSmallPoly g, int logn)
    {
        int n, u;
        n = 1 << logn;
        FalconShortPoly tmp = new FalconShortPoly(n);
        FalconNTT h_ntt, tmp_ntt;

        for (u = 0; u < n; u++)
        {
            tmp.coeffs[u] = (short)FalconNTT.mq_conv_small(f.coeffs[u]);
            out.coeffs[u] = (short)FalconNTT.mq_conv_small(g.coeffs[u]);
        }
        h_ntt = new FalconNTT(out, logn);
        tmp_ntt = new FalconNTT(tmp, logn);
        for (u = 0; u < n; u++)
        {
            if (tmp_ntt.poly.coeffs[u] == 0)
            {
                return false;
            }
            h_ntt.poly.coeffs[u] = (short)FalconNTT.mq_div_12289(h_ntt.poly.coeffs[u], tmp_ntt.poly.coeffs[u]);
        }
        FalconShortPoly out_tmp = h_ntt.mq_iNTT(logn);
        for (int i = 0; i < n; i++)
        {
            out.coeffs[i] = out_tmp.coeffs[i];
        }
        return true;
    }
}
