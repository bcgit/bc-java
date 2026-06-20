package org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class FrodoKEMKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final FrodoKEMParameters params;

    public FrodoKEMKeyGenerationParameters(
        SecureRandom random,
        FrodoKEMParameters frodoParameters)
    {
        super(random, 256);
        this.params = frodoParameters;
    }

    public FrodoKEMParameters getParameters()
    {
        return params;
    }
}
