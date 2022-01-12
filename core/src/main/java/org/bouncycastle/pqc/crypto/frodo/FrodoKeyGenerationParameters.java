package org.bouncycastle.pqc.crypto.frodo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class FrodoKeyGenerationParameters
    extends KeyGenerationParameters
{
    private FrodoParameters params;

    public FrodoKeyGenerationParameters(
        SecureRandom random,
        FrodoParameters frodoParameters)
    {
        super(random, 256);
        this.params = frodoParameters;
    }

    public FrodoParameters getParameters()
    {
        return params;
    }
}
