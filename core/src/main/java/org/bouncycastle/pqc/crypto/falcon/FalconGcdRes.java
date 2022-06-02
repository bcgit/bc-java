package org.bouncycastle.pqc.crypto.falcon;

class FalconGcdRes
{
    boolean res;
    FalconBigInt u;
    FalconBigInt v;

    FalconGcdRes()
    {
        this.res = false;
    }

    FalconGcdRes(boolean res, FalconBigInt u, FalconBigInt v)
    {
        this.res = res;
        this.u = u;
        this.v = v;
    }

    boolean is_one()
    {
        return this.res;
    }
}
