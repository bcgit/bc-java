package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

public class SRP6Group
{
    private BigInteger N, g;

    public SRP6Group(BigInteger N, BigInteger g)
    {
        this.N = N;
        this.g = g;
    }

    public BigInteger getG()
    {
        return g;
    }

    public BigInteger getN()
    {
        return N;
    }
}
