package org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class MLKEMKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final MLKEMParameters params;

    public MLKEMKeyGenerationParameters(
        SecureRandom random,
        MLKEMParameters kyberParameters)
    {
        super(random, 256);
        this.params = kyberParameters;
    }

    public MLKEMParameters getParameters()
    {
        return params;
    }
}
