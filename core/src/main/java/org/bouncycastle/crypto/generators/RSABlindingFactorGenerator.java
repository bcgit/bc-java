package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.BigIntegers;

/**
 * Generate a random factor suitable for use with RSA blind signatures
 * as outlined in Chaum's blinding and unblinding as outlined in
 * "Handbook of Applied Cryptography", page 475.
 */
public class RSABlindingFactorGenerator
{
    private static BigInteger TWO = BigInteger.valueOf(2);

    private RSAKeyParameters key;
    private SecureRandom random;

    /**
     * Initialise the factor generator
     *
     * @param param the necessary RSA key parameters.
     */
    public void init(
        CipherParameters param)
    {
        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;

            key = (RSAKeyParameters)rParam.getParameters();
            random = rParam.getRandom();
        }
        else
        {
            key = (RSAKeyParameters)param;
            random = CryptoServicesRegistrar.getSecureRandom();
        }

        if (key instanceof RSAPrivateCrtKeyParameters)
        {
            throw new IllegalArgumentException("generator requires RSA public key");
        }
    }

    /**
     * Generate a suitable blind factor for the public key the generator was initialised with.
     *
     * @return a random blind factor
     */
    public BigInteger generateBlindingFactor()
    {
        if (key == null)
        {
            throw new IllegalStateException("generator not initialised");
        }

        BigInteger m = key.getModulus();
        int length = m.bitLength() - 1; // must be less than m.bitLength()

        BigInteger factor;
        do
        {
            factor = BigIntegers.createRandomBigInteger(length, random);
        }
        while (factor.compareTo(TWO) < 0 || !BigIntegers.modOddIsCoprime(m, factor));

        return factor;
    }
}
