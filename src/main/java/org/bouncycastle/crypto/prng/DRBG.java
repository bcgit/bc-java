package org.bouncycastle.crypto.prng;

public interface DRBG {
    
    int generate(byte[] output, byte[] additionalInput, int inOff, int inLen);

    void reseed(byte[] additionalInput);
}
