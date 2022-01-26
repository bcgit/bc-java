package org.bouncycastle.pqc.crypto.saber;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class SABERKeyGenerationParameters
    extends KeyGenerationParameters
{
    private SABERParameters params;

    public SABERKeyGenerationParameters(
            SecureRandom random,
            SABERParameters saberParameters)
    {
        super(random, 256);
        this.params = saberParameters;
    }

    public SABERParameters getParameters()
    {
        return params;
    }
}
