package org.bouncycastle.pqc.crypto.smaugt;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SmaugTKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final SmaugTParameters params;

    public SmaugTKeyGenerationParameters(SecureRandom random, SmaugTParameters smaugTParameters)
    {
        super(random, 256);
        this.params = smaugTParameters;
    }

    public SmaugTParameters getParameters()
    {
        return params;
    }
}
