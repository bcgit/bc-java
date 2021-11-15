package org.bouncycastle.pqc.crypto.sphincsplus;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SPHINCSPlusKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final SPHINCSPlusParameters parameters;

    public SPHINCSPlusKeyGenerationParameters(SecureRandom random, SPHINCSPlusParameters parameters)
    {
        super(random, -1);
        this.parameters = parameters;
    }

    SPHINCSPlusParameters getParameters()
    {
        return parameters;
    }
}
