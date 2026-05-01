package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * @deprecated use org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters
 */
@Deprecated
public class MLDSAKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final MLDSAParameters params;

    public MLDSAKeyGenerationParameters(
        SecureRandom random,
        MLDSAParameters mldsaParameters)
    {
        super(random, 256);
        this.params = mldsaParameters;
    }

    public MLDSAParameters getParameters()
    {
        return params;
    }
}
