package org.bouncycastle.pqc.crypto.sqisign;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SQIsignKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final SQIsignParameters params;

    public SQIsignKeyGenerationParameters(SecureRandom random, SQIsignParameters params)
    {
        super(random, -1);
        this.params = params;
    }

    public SQIsignParameters getParameters()
    {
        return params;
    }
}
