package org.bouncycastle.pqc.crypto.falcon;

class FalconIntPoly
{
    int[] coeffs;

    FalconIntPoly(int n)
    {
        this.coeffs = new int[n];
    }

    FalconIntPoly(int[] coeffs)
    {
        this.coeffs = coeffs.clone();
    }

    void add(FalconIntPoly b)
    {
        for (int i = 0; i < this.coeffs.length; i++)
        {
            this.coeffs[i] += b.coeffs[i];
        }
    }

    void sub(FalconIntPoly b)
    {
        for (int i = 0; i < this.coeffs.length; i++)
        {
            this.coeffs[i] -= b.coeffs[i];
        }
    }

}
