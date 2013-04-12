package org.bouncycastle.crypto.prng;

import java.security.SecureRandom;

public class BasicEntropySource
    implements EntropySource
{
    private final SecureRandom _sr;
    private final boolean      _predictionResistant;

    public BasicEntropySource(SecureRandom random, boolean isPredictionResistant)
    {
        _sr = random;
        _predictionResistant = isPredictionResistant;
    }

    public boolean isPredictionResistant()
    {
        return _predictionResistant;
    }

    public byte[] getEntropy(int length)
    {
        byte[] rv = new byte[length];

        _sr.nextBytes(rv);

        return rv;
    }
}
