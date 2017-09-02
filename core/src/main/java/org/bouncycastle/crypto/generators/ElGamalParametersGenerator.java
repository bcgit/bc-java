package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.params.ElGamalParameters;

public class ElGamalParametersGenerator
{
    private int             size;
    private int             certainty;
    private SecureRandom    random;

    public void init(
        int             size,
        int             certainty,
        SecureRandom    random)
    {
        this.size = size;
        this.certainty = certainty;
        this.random = random;
    }

    /**
     * which generates the p and g values from the given parameters,
     * returning the ElGamalParameters object.
     * <p>
     * Note: can take a while...
     *
     * @return a generated ElGamal parameters object.
     */
    public ElGamalParameters generateParameters()
    {
        //
        // find a safe prime p where p = 2*q + 1, where p and q are prime.
        //
        BigInteger[] safePrimes = DHParametersHelper.generateSafePrimes(size, certainty, random);

        BigInteger p = safePrimes[0];
        BigInteger q = safePrimes[1];
        BigInteger g = DHParametersHelper.selectGenerator(p, q, random);

        return new ElGamalParameters(p, g);
    }
}
