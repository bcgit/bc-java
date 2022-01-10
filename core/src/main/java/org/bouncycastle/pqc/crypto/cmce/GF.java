package org.bouncycastle.pqc.crypto.cmce;

abstract class GF
{
    protected final int GFBITS;
    protected final int GFMASK;//  = ((1 << GFBITS) - 1);

    public GF(int gfbits)
    {
        GFBITS = gfbits;
        GFMASK = ((1 << GFBITS) - 1);

    }

    short gf_iszero(short a)
    {
        int t = a;

        t -= 1;
        t >>>= 19;

        return (short) t;
    }

    short gf_add(short left, short right)
    {
        return (short) (left ^ right);
    }

    abstract protected short gf_mul(short left, short right);
    abstract protected short gf_frac(short den, short num);
    abstract protected short gf_inv(short input);

}
