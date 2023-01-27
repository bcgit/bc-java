package org.bouncycastle.jcajce.provider.drbg;

import java.security.SecureRandom;

import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;

class IncrementalEntropySourceProvider
    implements EntropySourceProvider
{
    private final SecureRandom random;
    private final boolean predictionResistant;

    /**
     * Create a entropy source provider based on the passed in SecureRandom.
     *
     * @param random                the SecureRandom to base EntropySource construction on.
     * @param isPredictionResistant boolean indicating if the SecureRandom is based on prediction resistant entropy or not (true if it is).
     */
    public IncrementalEntropySourceProvider(SecureRandom random, boolean isPredictionResistant)
    {
        this.random = random;
        this.predictionResistant = isPredictionResistant;
    }

    /**
     * Return an entropy source that will create bitsRequired bits of entropy on
     * each invocation of getEntropy().
     *
     * @param bitsRequired size (in bits) of entropy to be created by the provided source.
     * @return an EntropySource that generates bitsRequired bits of entropy on each call to its getEntropy() method.
     */
    public EntropySource get(final int bitsRequired)
    {
        return new IncrementalEntropySource()
        {
            final int numBytes = (bitsRequired + 7) / 8;

            public boolean isPredictionResistant()
            {
                return predictionResistant;
            }

            public byte[] getEntropy()
            {
                try
                {
                    return getEntropy(0);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("initial entropy fetch interrupted"); // should never happen
                }
            }

            public byte[] getEntropy(long pause)
                throws InterruptedException
            {
                byte[] seed = new byte[numBytes];
                for (int i = 0; i < numBytes / 8; i++)
                {
                    // we need to be mindful that we may not be the only thread/process looking for entropy
                    sleep(pause);
                    byte[] rn = random.generateSeed(8);
                    System.arraycopy(rn, 0, seed, i * 8, rn.length);
                }

                int extra = numBytes - ((numBytes / 8) * 8);
                if (extra != 0)
                {
                    sleep(pause);
                    byte[] rn = random.generateSeed(extra);
                    System.arraycopy(rn, 0, seed, seed.length - rn.length, rn.length);
                }

                return seed;
            }

            public int entropySize()
            {
                return bitsRequired;
            }
        };
    }

    private static void sleep(long ms)
            throws InterruptedException
    {
        if (ms != 0)
        {
            Thread.sleep(ms);
        }
    }
}
