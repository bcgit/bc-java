package org.bouncycastle.mls.crypto;

public interface MlsAead
{
    int getKeySize();

    int getNonceSize();

    byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] pt);

    byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] pt);
}
