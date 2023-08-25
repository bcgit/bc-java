package org.bouncycastle.jcajce.spec;

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public class KEMGenerateSpec
    implements AlgorithmParameterSpec
{
    private final PublicKey publicKey;
    private final String keyAlgorithmName;
    private final int keySizeInBits;

    public KEMGenerateSpec(PublicKey publicKey, String keyAlgorithmName)
    {
        this(publicKey, keyAlgorithmName, 256);
    }

    public KEMGenerateSpec(PublicKey publicKey, String keyAlgorithmName, int keySizeInBits)
    {
        this.publicKey = publicKey;
        this.keyAlgorithmName = keyAlgorithmName;
        this.keySizeInBits = keySizeInBits;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public String getKeyAlgorithmName()
    {
        return keyAlgorithmName;
    }

    public int getKeySize()
    {
        return keySizeInBits;
    }
}
