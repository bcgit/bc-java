package org.bouncycastle.tls.crypto;

import java.io.IOException;

public interface TlsAEADCipher
{
    void setKey(byte[] key) throws IOException;

    /**
     * Initialise the parameters for the AEAD operator.
     *
     * @param nonce the nonce.
     * @param macSize MAC size in bytes.
     * @param additionalData any additional data to be included in the MAC calculation.
     * @throws IOException if the parameters are inappropriate.
     */
    void init(byte[] nonce, int macSize, byte[] additionalData) throws IOException;

    int getOutputSize(int inputLength);

    int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException;
}
