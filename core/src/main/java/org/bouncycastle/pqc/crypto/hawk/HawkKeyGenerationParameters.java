package org.bouncycastle.pqc.crypto.hawk;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Key generation parameters for Hawk. Carries the source of randomness and the
 * selected {@link HawkParameters} parameter set.
 */
public class HawkKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final HawkParameters params;

    public HawkKeyGenerationParameters(
        SecureRandom random,
        HawkParameters params)
    {
        super(random, 256);
        this.params = params;
    }

    public HawkParameters getParameters()
    {
        return params;
    }
}

