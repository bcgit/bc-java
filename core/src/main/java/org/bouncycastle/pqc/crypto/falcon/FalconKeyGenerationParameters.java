package org.bouncycastle.pqc.crypto.falcon;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class FalconKeyGenerationParameters
    extends KeyGenerationParameters
{

    private FalconParameters param;

    public FalconKeyGenerationParameters(SecureRandom random, FalconParameters param)
    {
        super(random, 320);
        this.param = param;
    }

    public FalconParameters getParameters()
    {
        return this.param;
    }
}
