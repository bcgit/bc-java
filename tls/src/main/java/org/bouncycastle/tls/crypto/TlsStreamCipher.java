package org.bouncycastle.tls.crypto;

import java.io.IOException;

public interface TlsStreamCipher
{
    void setKey(byte[] key) throws IOException;

    /**
     * Initialise the parameters for stream cipher.
     *
     * @param nonce the nonce for the stream cipher.
     * @throws IOException if the parameters are inappropriate.
     */
    void init(byte[] nonce) throws IOException;

    int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException;
}
