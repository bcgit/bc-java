package org.bouncycastle.crypto.prng;

import java.security.SecureRandom;

public class X931SecureRandom
    extends SecureRandom
{
    private final boolean predictionResistant;
    private final SecureRandom randomSource;
    private final X931RNG drbg;

    X931SecureRandom(SecureRandom randomSource, X931RNG drbg, boolean predictionResistant)
    {
        this.randomSource = randomSource;
        this.drbg = drbg;
        this.predictionResistant = predictionResistant;
    }

    public void setSeed(byte[] seed)
    {
        synchronized (this)
        {
            if (randomSource != null)
            {
                this.randomSource.setSeed(seed);
            }
        }
    }

    public void setSeed(long seed)
    {
        synchronized (this)
        {
            // this will happen when SecureRandom() is created
            if (randomSource != null)
            {
                this.randomSource.setSeed(seed);
            }
        }
    }

    public void nextBytes(byte[] bytes)
    {
        synchronized (this)
        {
            // check if a reseed is required...
            if (drbg.generate(bytes, predictionResistant) < 0)
            {
                drbg.reseed();
                drbg.generate(bytes, predictionResistant);
            }
        }
    }

    public byte[] generateSeed(int numBytes)
    {
        return EntropyUtil.generateSeed(drbg.getEntropySource(), numBytes);
    }
}
