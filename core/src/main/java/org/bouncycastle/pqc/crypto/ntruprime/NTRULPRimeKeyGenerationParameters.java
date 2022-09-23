package org.bouncycastle.pqc.crypto.ntruprime;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class NTRULPRimeKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final NTRULPRimeParameters ntrulprParams;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random   the random byte source.
     * @param ntrulprParams   NTRU LPRime parameters
     */
    public NTRULPRimeKeyGenerationParameters(SecureRandom random, NTRULPRimeParameters ntrulprParams)
    {
        super(null != random ? random : CryptoServicesRegistrar.getSecureRandom(), 256);
        this.ntrulprParams = ntrulprParams;
    }

    public NTRULPRimeParameters getNtrulprParams()
    {
        return ntrulprParams;
    }
}
