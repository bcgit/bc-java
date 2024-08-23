package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class MLDSAKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final MLDSAParameters params;

    public MLDSAKeyGenerationParameters(
        SecureRandom random,
        MLDSAParameters dilithiumParameters)
    {
        super(random, 256);
        this.params = dilithiumParameters;
    }

    public MLDSAParameters getParameters()
    {
        return params;
    }
}
