package org.bouncycastle.pqc.crypto.haetae;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class HAETAEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final HAETAEParameters params;

    public HAETAEKeyGenerationParameters(
        SecureRandom random,
        HAETAEParameters HAETAEParameters)
    {
        super(random, 256);
        this.params = HAETAEParameters;
    }

    public HAETAEParameters getParameters()
    {
        return params;
    }
}
