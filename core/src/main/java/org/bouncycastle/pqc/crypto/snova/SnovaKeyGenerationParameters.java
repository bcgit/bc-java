package org.bouncycastle.pqc.crypto.snova;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SnovaKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final SnovaParameters params;

    public SnovaKeyGenerationParameters(SecureRandom random, SnovaParameters params)
    {
        super(random, -1); // Security parameter not used directly
        this.params = params;
    }

    public SnovaParameters getParameters()
    {
        return params;
    }
}
