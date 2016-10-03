package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/**
 * Carrier class for Diffie-Hellman group parameters.
 */
public class DHGroup
{
    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;

    /**
     * Base constructor.
     *
     * @param p the prime modulus.
     * @param g the base generator.
     */
    public DHGroup(BigInteger p, BigInteger g)
    {
        this(p, null, g);
    }

    /**
     * Base constructor with the prime factor of (p - 1).
     *
     * @param p the prime modulus.
     * @param q specifies the prime factor of (p - 1).
     * @param g the base generator.
     */
    public DHGroup(BigInteger p, BigInteger q, BigInteger g)
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
