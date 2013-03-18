package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.prng.EntropySource;

public class TestEntropySource implements EntropySource
{
    private byte[]      _vector;
    private int         _vectorPos = 0;
    private int         _vectorMax;
    
    private boolean     _predictionResistant;

    public TestEntropySource(byte[] testVector, boolean isPredictionResistant)
    {
        _vector = testVector;
        _vectorPos = 0;
        _vectorMax = _vector.length;
        _predictionResistant = isPredictionResistant;
    }

    public boolean isPredictionResistant()
    {
        return _predictionResistant;
    }

    public byte[] getEntropy(int length)
    {
        if (_vectorPos + length > _vectorMax) 
        {
            throw new IllegalStateException("Requested too many bytes.");
        }
        
        byte[] rv = new byte[length];
        System.arraycopy(_vector, _vectorPos, rv, 0, length);
        _vectorPos += length;
        return rv;
    }

}
