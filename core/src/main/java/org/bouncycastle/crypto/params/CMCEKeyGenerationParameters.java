package org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class CMCEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final CMCEParameters params;

    public CMCEKeyGenerationParameters(
        SecureRandom random,
        CMCEParameters cmceParameters)
    {
        super(random, 256);
        this.params = cmceParameters;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }
}
