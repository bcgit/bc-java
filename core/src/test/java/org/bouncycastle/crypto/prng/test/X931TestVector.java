package org.bouncycastle.crypto.prng.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.prng.EntropySourceProvider;

public class X931TestVector
{
    private final BlockCipher engine;
    private final EntropySourceProvider entropyProvider;
    private final String key;
    private final String dateTimeVector;
    private final boolean predictionResistant;
    private final String[] expected;

    public X931TestVector(BlockCipher engine, EntropySourceProvider entropyProvider, String key, String dateTimeVector, boolean predictionResistant, String[] expected)
    {
        this.engine = engine;
        this.entropyProvider = entropyProvider;
        this.key = key;


        this.dateTimeVector = dateTimeVector;
        this.predictionResistant = predictionResistant;
        this.expected = expected;
    }

    public String getDateTimeVector()
    {
        return dateTimeVector;
    }

    public BlockCipher getEngine()
    {
        return engine;
    }

    public EntropySourceProvider getEntropyProvider()
    {
        return entropyProvider;
    }

    public String[] getExpected()
    {
        return expected;
    }

    public String getKey()
    {
        return key;
    }

    public boolean isPredictionResistant()
    {
        return predictionResistant;
    }
}
