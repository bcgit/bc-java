package org.bouncycastle.pqc.crypto.hawk;

class SmallPrime
{
    public final long p;
    public final long p0i;
    public final long R2;
    public final long g;
    public final long ig;
    public final long s;

    public SmallPrime(long p, long p0i, long R2, long g, long ig, long s)
    {
        this.p = p;
        this.p0i = p0i;
        this.R2 = R2;
        this.g = g;
        this.ig = ig;
        this.s = s;
    }
}
