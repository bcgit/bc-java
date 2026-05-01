package org.bouncycastle.pqc.crypto.falcon;

class SamplerCtx
{

    double sigma_min;
    FalconRNG p;

    SamplerCtx()
    {
        this.sigma_min = 0.0;
        this.p = new FalconRNG();
    }
}
