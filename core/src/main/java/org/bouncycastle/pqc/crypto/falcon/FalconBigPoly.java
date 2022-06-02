package org.bouncycastle.pqc.crypto.falcon;

class FalconBigPoly
{
    FalconBigInt[] coeffs;

    FalconBigPoly(int n)
    {
        this.coeffs = new FalconBigInt[n];
    }

    FalconBigPoly(FalconBigInt[] coeffs)
    {
        this.coeffs = coeffs;
    }

    FalconIntPoly toIntPoly()
    { // assumes it contains only 1 word big ints
        FalconIntPoly res = new FalconIntPoly(this.coeffs.length);
        for (int i = 0; i < this.coeffs.length; i++)
        {
            res.coeffs[i] = this.coeffs[i].one_to_plain();
        }
        return res;
    }

    void sub_scaled(int Flen,
                    FalconBigPoly f, int flen,
                    FalconIntPoly k,
                    int sch, int scl, int logn)
    {
        int n, u;
        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            int kf;
            int v;
            FalconBigInt x;
            FalconBigInt[] y;
            int index;

            index = u;
            kf = -k.coeffs[u];
            x = this.coeffs[index];
            y = f.coeffs;
            for (v = 0; v < n; v++)
            {
                x.add_scaled_mul_small(Flen, y[v], flen, kf, sch, scl);
                if (u + v == n - 1)
                {
                    index = 0;
                    x = this.coeffs[index];
                    kf = -kf;
                }
                else
                {
                    index++;
                    x = this.coeffs[index];
                }
            }
        }
    }
}
