package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/**
 * Carrier class for SRP-6 group parameters.
 */
public class SRP6Group
{
    private BigInteger N, g;

    /**
     * Base constructor.
     *
     * @param N the N value.
     * @param g the g value.
     */
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
