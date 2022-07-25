package org.bouncycastle.pqc.crypto.crystals.kyber;

class Reduce
{

    public static short montgomeryReduce(int a)
    {
        int t;
        short u;

        u = (short)(a * KyberEngine.KyberQinv);
        t = (int)(u * KyberEngine.KyberQ);
        t = a - t;
        t >>= 16;
        return (short)t;
    }

    public static short barretReduce(short a)
    {
        short t;
        long shift = (((long)1) << 26);
        short v = (short)((shift + (KyberEngine.KyberQ / 2)) / KyberEngine.KyberQ);
        t = (short)((v * a) >> 26);
        t = (short)(t * KyberEngine.KyberQ);
        return (short)(a - t);
    }

    public static short conditionalSubQ(short a)
    {
        a -= KyberEngine.KyberQ;
        a += (a >> 15) & KyberEngine.KyberQ;
        return a;
    }

}
