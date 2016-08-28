package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

public class TlsDHParameters
{
    private final BigInteger p;
    private final BigInteger g;
    private final BigInteger q;

    public TlsDHParameters(BigInteger p, BigInteger g)
    {
        this(p, g, null);
    }

    public TlsDHParameters(BigInteger p, BigInteger g, BigInteger q)
    {
        this.p = p;
        this.g = g;
        this.q = q;
    }

    public BigInteger getG()
    {
        return g;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }
}
