package org.bouncycastle.pqc.crypto.crystals.dilithium;

class Reduce
{
    static int montgomeryReduce(long a)
    {
        int t;
        t = (int)(a * DilithiumEngine.DilithiumQinv);
        t = (int)((a - ((long)t) * DilithiumEngine.DilithiumQ) >>> 32);
        // System.out.printf("%d, ", t);
        return t;

    }

    static int reduce32(int a)
    {
        int t;
        t = (a + (1 << 22)) >> 23;
        t = a - t * DilithiumEngine.DilithiumQ;
        return t;
    }

    static int conditionalAddQ(int a)
    {
        a += (a >> 31) & DilithiumEngine.DilithiumQ;
        return a;
    }
}
