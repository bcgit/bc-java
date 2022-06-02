package org.bouncycastle.pqc.crypto.falcon;


class FalconKeys
{
    FalconSmallPoly f;
    FalconSmallPoly g;
    FalconSmallPoly F;
    FalconSmallPoly G;
    FalconShortPoly h;

    FalconKeys(FalconSmallPoly f, FalconSmallPoly g, FalconSmallPoly F, FalconSmallPoly G, FalconShortPoly h)
    {
        this.f = f;
        this.g = g;
        this.F = F;
        this.G = G;
        this.h = h;
    }
}
