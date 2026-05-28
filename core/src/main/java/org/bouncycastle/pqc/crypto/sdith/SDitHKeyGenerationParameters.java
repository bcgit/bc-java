package org.bouncycastle.pqc.crypto.sdith;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SDitHKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final SDitHParameters params;

    public SDitHKeyGenerationParameters(SecureRandom random, SDitHParameters params)
    {
        super(random, 256);
        this.params = params;
    }

    public SDitHParameters getParameters()
    {
        return params;
    }
}
