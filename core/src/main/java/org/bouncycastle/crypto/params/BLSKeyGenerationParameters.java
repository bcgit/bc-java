package org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class BLSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final BLSParameters params;

    public BLSKeyGenerationParameters(
        SecureRandom random,
        BLSParameters blsParameters)
    {
        super(random, 256);
        this.params = blsParameters;
    }

    public BLSParameters getParameters()
    {
        return params;
    }
}
