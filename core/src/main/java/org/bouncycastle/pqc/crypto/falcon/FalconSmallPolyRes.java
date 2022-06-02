package org.bouncycastle.pqc.crypto.falcon;

class FalconSmallPolyRes
{
    boolean success;
    FalconSmallPoly poly;

    FalconSmallPolyRes()
    {
        this.success = false;
    }

    FalconSmallPolyRes(FalconSmallPoly p)
    {
        this.success = true;
        this.poly = p;
    }
}
