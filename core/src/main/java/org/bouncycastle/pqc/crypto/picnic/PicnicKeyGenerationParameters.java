package org.bouncycastle.pqc.crypto.picnic;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class PicnicKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final PicnicParameters parameters;

    public PicnicKeyGenerationParameters(SecureRandom random, PicnicParameters parameters)
    {
        super(random, -1);
        this.parameters = parameters;
    }

    public PicnicParameters getParameters()
    {
        return parameters;
    }
}
