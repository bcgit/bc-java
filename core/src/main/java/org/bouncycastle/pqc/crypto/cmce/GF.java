package org.bouncycastle.pqc.crypto.cmce;

abstract class GF
{
    GF()
    {
    }

    final short gf_iszero(short a)
    {
        return (short)((a - 1) >> 31);
    }

    abstract protected void gf_mul_poly(int length, int[] poly, short[] out, short[] left, short[] right, int[] temp);
    abstract protected void gf_sqr_poly(int length, int[] poly, short[] out, short[] input, int[] temp);

    abstract protected short gf_frac(short den, short num);
    abstract protected short gf_inv(short input);
    abstract protected short gf_mul(short left, short right);
    abstract protected int gf_mul_ext(short left, short right);
    abstract protected short gf_reduce(int input);
    abstract protected short gf_sq(short input);
    abstract protected int gf_sq_ext(short input);
}
