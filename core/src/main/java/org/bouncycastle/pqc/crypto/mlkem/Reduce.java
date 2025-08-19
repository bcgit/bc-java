package org.bouncycastle.pqc.crypto.mlkem;

class Reduce
{

    public static short montgomeryReduce(int a)
    {
        int t;
        short u;

        u = (short)(a * MLKEMEngine.KyberQinv);
        t = (int)(u * MLKEMEngine.KyberQ);
        t = a - t;
        t >>= 16;
        return (short)t;
    }

    public static short barretReduce(short a)
    {
        short t;
        long shift = (((long)1) << 26);
        short v = (short)((shift + (MLKEMEngine.KyberQ / 2)) / MLKEMEngine.KyberQ);
        t = (short)((v * a) >> 26);
        t = (short)(t * MLKEMEngine.KyberQ);
        return (short)(a - t);
    }

    public static short conditionalSubQ(short a)
    {
        a -= MLKEMEngine.KyberQ;
        a += (a >> 15) & MLKEMEngine.KyberQ;
        return a;
    }

    // NB: We only care about the sign bit of the result: it will be 1 iff the argument was in range
    static int checkModulus(short a)
    {
        return a - MLKEMEngine.KyberQ;
    }
}
