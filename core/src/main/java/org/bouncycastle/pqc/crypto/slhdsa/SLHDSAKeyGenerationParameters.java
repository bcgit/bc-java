package org.bouncycastle.pqc.crypto.slhdsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * @deprecated use org.bouncycastle.crypto.params.SLHDSAKeyGenerationParameters
 */
@Deprecated
public class SLHDSAKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final SLHDSAParameters parameters;

    public SLHDSAKeyGenerationParameters(SecureRandom random, SLHDSAParameters parameters)
    {
        super(random, -1);
        this.parameters = parameters;
    }

    SLHDSAParameters getParameters()
    {
        return parameters;
    }
}
