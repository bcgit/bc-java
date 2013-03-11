package org.bouncycastle.crypto.prng;

public interface DRBGDerivationFunction {
    
    int getSeedlength();

    int getSecurityStrength();

    byte[] getDFBytes(byte[] seedMaterial, int seedlength);
    byte[] getBytes(byte[] input);

    byte[] getByteGen(byte[] v, int numberOfBits);
    
}
