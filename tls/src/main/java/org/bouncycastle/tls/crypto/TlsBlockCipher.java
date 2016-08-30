package org.bouncycastle.tls.crypto;

import java.io.IOException;

public interface TlsBlockCipher
{
    void setKey(byte[] key) throws IOException;

    /**
     * Initialise the parameters for operator.
     *
     * @param iv the initialization vector.
     * @throws IOException if the parameters are inappropriate.
     */
    void init(byte[] iv) throws IOException;

    int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException;

    int getBlockSize();
}
