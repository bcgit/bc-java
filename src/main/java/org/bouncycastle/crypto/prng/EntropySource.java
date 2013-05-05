package org.bouncycastle.crypto.prng;

public interface EntropySource
{
    boolean isPredictionResistant();

    byte[] getEntropy();
}
