package org.bouncycastle.pqc.crypto.falcon;

class SamplerCtx
{

    FalconFPR sigma_min;
    FalconRNG p;

    SamplerCtx()
    {
        this.sigma_min = new FalconFPR(0.0);
        this.p = new FalconRNG();
    }
}
