package org.bouncycastle.pqc.crypto.ntruplus;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class NTRUPlusKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final NTRUPlusParameters params;

    public NTRUPlusKeyGenerationParameters(
        SecureRandom random,
        NTRUPlusParameters mayoParameters)
    {
        super(random, 256);
        this.params = mayoParameters;
    }

    public NTRUPlusParameters getParameters()
    {
        return params;
    }
}
