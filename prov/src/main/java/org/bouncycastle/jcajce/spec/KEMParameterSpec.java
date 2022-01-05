package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class KEMParameterSpec
    implements AlgorithmParameterSpec
{
    private final String wrappingKeyAlgorithmName;

    public KEMParameterSpec(String wrappingKeyAlgorithmName)
    {
        this.wrappingKeyAlgorithmName = wrappingKeyAlgorithmName;
    }

    public String getWrappingKeyAlgorithmName()
    {
        return wrappingKeyAlgorithmName;
    }
}
