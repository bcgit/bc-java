package org.bouncycastle.crypto.random;

import java.security.SecureRandom;

import org.bouncycastle.crypto.prng.BasicEntropySource;
import org.bouncycastle.crypto.prng.SP80090DRBG;
import org.bouncycastle.crypto.prng.EntropySource;

public class SP800SecureRandom
    extends SecureRandom
{
    private final DRBGProvider drbgProvider;
    private final boolean predictionResistant;
    private final SecureRandom randomSource;
    private final boolean randomPredictionResistant;

    private SP80090DRBG drbg;

    SP800SecureRandom(SecureRandom randomSource, boolean randomPredictionResistant, DRBGProvider drbgProvider, boolean predictionResistant)
    {
        this.randomSource = randomSource;
        this.randomPredictionResistant = randomPredictionResistant;
        this.drbgProvider = drbgProvider;
        this.predictionResistant = predictionResistant;
    }

    public void setSeed(byte[] seed)
    {
        synchronized (this)
        {
            this.randomSource.setSeed(seed);
        }
    }

    public void setSeed(long seed)
    {
        synchronized (this)
        {
            // this will happen when SecureRandom() is created.
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
            if (drbg == null)
            {
                drbg = drbgProvider.get(new BasicEntropySource(randomSource, randomPredictionResistant));
            }

            drbg.generate(bytes, null, predictionResistant);
        }
    }

    public byte[] generateSeed(int numBytes)
    {
        byte[] bytes = new byte[numBytes];

        this.nextBytes(bytes);

        return bytes;
    }
}
