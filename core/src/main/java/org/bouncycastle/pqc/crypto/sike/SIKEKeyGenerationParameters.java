package org.bouncycastle.pqc.crypto.sike;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class SIKEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private SIKEParameters params;

    public SIKEKeyGenerationParameters(
            SecureRandom random,
            SIKEParameters sikeParameters
    )
    {
        super(random, 256);
        this.params = sikeParameters;
    }
    public SIKEParameters getParameters()
    {
        return params;
    }
}
