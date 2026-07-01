package org.bouncycastle.pqc.crypto.aimer;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class AIMerKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final AIMerParameters params;

    public AIMerKeyGenerationParameters(
        SecureRandom random,
        AIMerParameters params)
    {
        super(random, 256);
        this.params = params;
    }

    public AIMerParameters getParameters()
    {
        return params;
    }
}
