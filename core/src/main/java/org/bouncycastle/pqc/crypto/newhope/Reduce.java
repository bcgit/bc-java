package org.bouncycastle.pqc.crypto.newhope;

class Reduce
{
    static final int QInv = 12287; // -inverse_mod(p,2^18)
    static final int RLog = 18;
    static final int RMask = (1 << RLog) - 1;

    static short montgomery(int a)
    {
        int u = a * QInv;
        u &= RMask;
        u *= Params.Q;
        u += a;
        return (short)(u >>> RLog);
    }

    static short barrett(short a)
    {
        int t = a & 0xFFFF;
        int u = (t * 5) >>> 16;
        u *= Params.Q;
        return (short)(t - u);
    }
}
