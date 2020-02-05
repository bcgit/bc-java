package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class LMSKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final LMSParameters lmsParams;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random   the random byte source.
     */
    public LMSKeyGenerationParameters(LMSParameters lmsParams, SecureRandom random)
    {
        super(random, 128); // TODO: need something for "strength"
        this.lmsParams = lmsParams;
    }

    public LMSParameters getParameters()
    {
        return lmsParams;
    }
}
