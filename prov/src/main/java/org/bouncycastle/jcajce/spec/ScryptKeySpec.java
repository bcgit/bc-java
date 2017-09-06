package org.bouncycastle.jcajce.spec;

import java.security.spec.KeySpec;

import org.bouncycastle.util.Arrays;

/**
 * Key spec for use with the scrypt SecretKeyFactory.
 */
public class ScryptKeySpec
    implements KeySpec
{
    private final char[] password;
    private final byte[] salt;
    private final int costParameter;
    private final int blockSize;
    private final int parallelizationParameter;
    private final int keySize;

    public ScryptKeySpec(char[] password, byte[] salt, int costParameter, int blockSize, int parallelizationParameter, int keySize)
    {

        this.password = password;
        this.salt = Arrays.clone(salt);
        this.costParameter = costParameter;
        this.blockSize = blockSize;
        this.parallelizationParameter = parallelizationParameter;
        this.keySize = keySize;
    }

    public char[] getPassword()
    {
        return password;
    }

    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    public int getCostParameter()
    {
        return costParameter;
    }

    public int getBlockSize()
    {
        return blockSize;
    }

    public int getParallelizationParameter()
    {
        return parallelizationParameter;
    }

    /**
     * Key length (in bits).
     *
     * @return length of the key to generate in bits.
     */
    public int getKeyLength()
    {
        return keySize;
    }
}