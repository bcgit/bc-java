package org.bouncycastle.crypto;

import java.security.SecureRandom;

import org.bouncycastle.crypto.constraints.DefaultServiceProperties;

/**
 * The base class for symmetric, or secret, cipher key generators.
 */
public class CipherKeyGenerator
{
    protected SecureRandom  random;
    protected int           strength;

    /**
     * initialise the key generator.
     *
     * @param param the parameters to be used for key generation
     */
    public void init(
        KeyGenerationParameters param)
    {
        this.random = param.getRandom();
        this.strength = (param.getStrength() + 7) / 8;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("SymKeyGen", param.getStrength()));
    }

    /**
     * generate a secret key.
     *
     * @return a byte array containing the key value.
     */
    public byte[] generateKey()
    {
        byte[]  key = new byte[strength];

        random.nextBytes(key);

        return key;
    }
}
