package org.bouncycastle.pqc.crypto.faest;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class FaestKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final FaestParameters params;

    public FaestKeyGenerationParameters(SecureRandom random, FaestParameters params)
    {
        super(random, -1);
        this.params = params;
    }

    public FaestParameters getParameters()
    {
        return params;
    }
}
