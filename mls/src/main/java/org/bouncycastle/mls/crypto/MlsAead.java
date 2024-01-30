package org.bouncycastle.mls.crypto;

import org.bouncycastle.crypto.InvalidCipherTextException;

public interface MlsAead
{
    int getKeySize();

    int getNonceSize();

    byte[] open(byte[] key, byte[] nonce, byte[] aad, byte[] pt)
        throws InvalidCipherTextException;

    byte[] seal(byte[] key, byte[] nonce, byte[] aad, byte[] pt)
        throws InvalidCipherTextException;
}
