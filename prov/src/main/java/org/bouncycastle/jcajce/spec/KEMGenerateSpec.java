package org.bouncycastle.jcajce.spec;

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;

public class KEMGenerateSpec
    implements AlgorithmParameterSpec
{
    private final PublicKey publicKey;
    private final String keyAlgorithmName;

    public KEMGenerateSpec(PublicKey publicKey, String keyAlgorithmName)
    {
        this.publicKey = publicKey;
        this.keyAlgorithmName = keyAlgorithmName;
    }

    public PublicKey getPublicKey()
    {
        return publicKey;
    }

    public String getKeyAlgorithmName()
    {
        return keyAlgorithmName;
    }
}
