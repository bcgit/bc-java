package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

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

    public  FrodoParameters getParameters()
    {
        return params;
    }
}
