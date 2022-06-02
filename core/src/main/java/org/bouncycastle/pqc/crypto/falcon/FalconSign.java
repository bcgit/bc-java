package org.bouncycastle.pqc.crypto.falcon;

class FalconSign
{
    /*
     * gets size of LDL tree for polynomials of 2^logn
     */
    static int ffLDL_treesize(int logn)
    {
        return (logn + 1) << logn;
    }

    /*
     * inner function for ffLDL_fft()
     */
    static void ffLDL_fft_inner(int tree, FalconFPR[] tree_a,
                                int g0, FalconFPR[] g0_a,
                                int g1, FalconFPR[] g1_a,
                                int logn,
                                int tmp, FalconFPR[] tmp_a)
    {
        int n, hn;
        n = 1 << logn;
        if (n == 1)
        {
            tree_a[tree] = g0_a[g0];
            return;
        }
        hn = n >> 1;

    }
}
