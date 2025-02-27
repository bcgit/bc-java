package org.bouncycastle.pqc.crypto.mayo;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class MayoKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final MayoParameters params;

    public MayoKeyGenerationParameters(
        SecureRandom random,
        MayoParameters mayoParameters)
    {
        super(random, 256);
        this.params = mayoParameters;
    }

    public MayoParameters getParameters()
    {
        return params;
    }
}
