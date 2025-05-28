package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class CrossKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final CrossParameters params;

    public CrossKeyGenerationParameters(
        SecureRandom random,
        CrossParameters CrossParameters)
    {
        super(random, 256);
        this.params = CrossParameters;
    }

    public CrossParameters getParameters()
    {
        return params;
    }
}
