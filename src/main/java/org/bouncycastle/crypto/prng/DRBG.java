package org.bouncycastle.crypto.prng;

public interface DRBG {
    
    int generate(byte[] output, byte[] additionalInput, boolean predictionResistant);

    void reseed(byte[] additionalInput);
}
