package org.bouncycastle.crypto.random;

import java.security.SecureRandom;

import org.bouncycastle.crypto.prng.BasicEntropySourceProvider;
import org.bouncycastle.crypto.prng.SP80090DRBG;

public class SP800SecureRandom
    extends SecureRandom
{
    private final DRBGProvider drbgProvider;
    private final boolean predictionResistant;
    private final SecureRandom randomSource;
    private final boolean randomPredictionResistant;
    private final int entropyBitsRequired;

    private SP80090DRBG drbg;

    SP800SecureRandom(SecureRandom randomSource, boolean randomPredictionResistant, DRBGProvider drbgProvider, boolean predictionResistant, int entropyBitsRequired)
    {
        this.randomSource = randomSource;
        this.randomPredictionResistant = randomPredictionResistant;
        this.drbgProvider = drbgProvider;
        this.predictionResistant = predictionResistant;
        this.entropyBitsRequired = entropyBitsRequired;
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
                drbg = drbgProvider.get(new BasicEntropySourceProvider(randomSource, randomPredictionResistant).get(entropyBitsRequired));
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
