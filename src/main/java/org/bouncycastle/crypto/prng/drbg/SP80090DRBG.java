package org.bouncycastle.crypto.prng.drbg;

public interface SP80090DRBG
{
    
    int generate(byte[] output, byte[] additionalInput, boolean predictionResistant);

    void reseed(byte[] additionalInput);
}
