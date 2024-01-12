package org.bouncycastle.mls.crypto;

public interface MlsKdf
{
    int getHashLength();

    byte[] extract(byte[] salt, byte[] ikm);

    byte[] expand(byte[] prk, byte[] info, int length);

}
