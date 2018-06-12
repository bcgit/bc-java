package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;

import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;

/**
 * Extension class for DHParameterSpec that wraps a DHDomainParameters object and provides the q domain parameter.
 */
public class DHDomainParameterSpec
    extends DHParameterSpec
{
    private final BigInteger q;
    private final BigInteger j;
    private final int m;

    private DHValidationParameters validationParameters;

    /**
     * Base constructor - use the values in an existing set of domain parameters.
     *
     * @param domainParameters the Diffie-Hellman domain parameters to wrap.
     */
    public DHDomainParameterSpec(DHParameters domainParameters)
    {
        this(domainParameters.getP(), domainParameters.getQ(), domainParameters.getG(), domainParameters.getJ(), domainParameters.getM(), domainParameters.getL());
        this.validationParameters = domainParameters.getValidationParameters();
    }

    /**
     * Minimal constructor for parameters able to be used to verify a public key, or use with MQV.
     *
     * @param p the prime p defining the Galois field.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param q specifies the prime factor of p - 1
     */
    public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g)
    {
        this(p, q, g, null, 0);
    }

    /**
     * Minimal constructor for parameters able to be used to verify a public key, or use with MQV, and a private value length.
     *
     * @param p the prime p defining the Galois field.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param q specifies the prime factor of p - 1
     * @param l the maximum bit length for the private value.
     */
    public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g, int l)
    {
        this(p, q, g, null, l);
    }

    /**
     * X9.42 parameters with private value length.
     *
     * @param p the prime p defining the Galois field.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param q specifies the prime factor of p - 1
     * @param j optionally specifies the value that satisfies the equation p = jq+1
     * @param l the maximum bit length for the private value.
     */
    public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g, BigInteger j, int l)
    {
        this(p, q, g, j, 0, l);
    }

    /**
     * Base constructor - the full domain parameter set.
     *
     * @param p the prime p defining the Galois field.
     * @param g the generator of the multiplicative subgroup of order g.
     * @param q specifies the prime factor of p - 1
     * @param j optionally specifies the value that satisfies the equation p = jq+1
     * @param m the minimum bit length for the private value.
     * @param l the maximum bit length for the private value.
     */
    public DHDomainParameterSpec(BigInteger p, BigInteger q, BigInteger g, BigInteger j, int m, int l)
    {
        super(p, g, l);
        this.q = q;
        this.j = j;
        this.m = m;
    }

    /**
     * Return the Q value for the domain parameter set.
     *
     * @return the value Q.
     */
    public BigInteger getQ()
    {
        return q;
    }

    /**
     * Return the J value for the domain parameter set if available.
     *
     * @return the value J, null otherwise.
     */
    public BigInteger getJ()
    {
        return j;
    }

    /**
     * Return the minimum bitlength for a private value to be generated from these parameters, 0 if not set.
     *
     * @return minimum bitlength for private value.
     */
    public int getM()
    {
        return m;
    }

    /**
     * Return the DHDomainParameters object we represent.
     *
     * @return the internal DHDomainParameters.
     */
    public DHParameters getDomainParameters()
    {
        return new DHParameters(getP(), getG(), q, m, getL(), j, validationParameters);
    }
}
