package org.bouncycastle.pqc.crypto.mirath;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class MirathKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final MirathParameters params;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random     the random byte source.
     * @param parameters
     */
    public MirathKeyGenerationParameters(SecureRandom random, MirathParameters parameters)
    {
        super(random, parameters.getSecurityLevel());
        this.params = parameters;
    }

    public MirathParameters getParameters()
    {
        return params;
    }
}
