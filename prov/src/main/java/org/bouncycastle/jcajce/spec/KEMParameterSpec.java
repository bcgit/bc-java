package org.bouncycastle.jcajce.spec;

/**
 *  @deprecated use KTSParameterSpec
 */
public class KEMParameterSpec
    extends KTSParameterSpec
{
    public KEMParameterSpec(String keyAlgorithmName)
    {
        this(keyAlgorithmName, 256);
    }

    public KEMParameterSpec(String keyAlgorithmName, int keySizeInBits)
    {
        super(keyAlgorithmName, keySizeInBits, null, null, null);
    }

    /**
     * Return the key size in bits if specified, -1 indicates no preference.
     *
     * @return key size, or -1.
     */
    public int getKeySizeInBits()
    {
        return getKeySize();
    }
}
