package org.bouncycastle.pqc.crypto.mldsa;

class Reduce
{
    static int montgomeryReduce(long a)
    {
        int t;
        t = (int)(a * MLDSAEngine.DilithiumQinv);
        t = (int)((a - ((long)t) * MLDSAEngine.DilithiumQ) >>> 32);
        // System.out.printf("%d, ", t);
        return t;

    }

    static int reduce32(int a)
    {
        int t;
        t = (a + (1 << 22)) >> 23;
        t = a - t * MLDSAEngine.DilithiumQ;
        return t;
    }

    static int conditionalAddQ(int a)
    {
        a += (a >> 31) & MLDSAEngine.DilithiumQ;
        return a;
    }
}
