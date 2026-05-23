package org.bouncycastle.pqc.crypto.uov;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class UOVKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final UOVParameters params;

    public UOVKeyGenerationParameters(SecureRandom random, UOVParameters params)
    {
        super(random, 256);
        this.params = params;
    }

    public UOVParameters getParameters()
    {
        return params;
    }
}
