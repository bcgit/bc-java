package org.bouncycastle.pqc.crypto.ntruprime;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class SNTRUPrimeKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final SNTRUPrimeParameters sntrupParams;

    /**
     * initialise the generator with a source of randomness
     * and a strength (in bits).
     *
     * @param random   the random byte source.
     * @param sntrupParams   Streamlined NTRU Prime parameters
     */
    public SNTRUPrimeKeyGenerationParameters(SecureRandom random, SNTRUPrimeParameters sntrupParams)
    {
        super(null != random ? random : CryptoServicesRegistrar.getSecureRandom(), 256);
        this.sntrupParams = sntrupParams;
    }

    public SNTRUPrimeParameters getSntrupParams()
    {
        return sntrupParams;
    }
}
