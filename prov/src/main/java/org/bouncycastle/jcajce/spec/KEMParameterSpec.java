package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class KEMParameterSpec
    implements AlgorithmParameterSpec
{
    private final String keyAlgorithmName;
    private final int keySizeInBits;

    public KEMParameterSpec(String keyAlgorithmName)
    {
        this(keyAlgorithmName, -1);
    }

    public KEMParameterSpec(String keyAlgorithmName, int keySizeInBits)
    {
        this.keyAlgorithmName = keyAlgorithmName;
        this.keySizeInBits = keySizeInBits;
    }

    /**
     * Return the name of the symmetric key algorithm for the key returned by this KEM.
     *
     * @return key algorithm name.
     */
    public String getKeyAlgorithmName()
    {
        return keyAlgorithmName;
    }

    /**
     * Return the key size in bits if specified, -1 indicates no preference.
     *
     * @return key size, or -1.
     */
    public int getKeySizeInBits()
    {
        return keySizeInBits;
    }
}
