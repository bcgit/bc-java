package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/**
 * Carrier class for Diffie-Hellman group parameters.
 */
public class DHGroup
{
    private final BigInteger g, p, q;
    private final int l;

    /**
     * Base constructor with the prime factor of (p - 1).
     *
     * @param p the prime modulus.
     * @param q specifies the prime factor of (p - 1).
     * @param g the base generator.
     */
    public DHGroup(BigInteger p, BigInteger q, BigInteger g, int l)
    {
        this.p = p;
        this.g = g;
        this.q = q;
        this.l = l;
    }

    public BigInteger getG()
    {
        return g;
    }

    public int getL()
    {
        return l;
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
