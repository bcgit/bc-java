package org.bouncycastle.crypto.prng.test;

import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;

public class TestEntropySourceProvider
    implements EntropySourceProvider
{
    private final byte[] data;
    private final boolean isPredictionResistant;

    protected TestEntropySourceProvider(byte[] data, boolean isPredictionResistant)
    {
        this.data = data;
        this.isPredictionResistant = isPredictionResistant;
    }

    public EntropySource get(final int bitsRequired)
    {
        return new EntropySource()
        {
            int index = 0;

            public boolean isPredictionResistant()
            {
                return isPredictionResistant;
            }

            public byte[] getEntropy()
            {
                byte[] rv = new byte[bitsRequired / 8];

                System.arraycopy(data, index, rv, 0, rv.length);

                index += bitsRequired / 8;

                return rv;
            }

            public int entropySize()
            {
                return bitsRequired;
            }
        };
    }
}
