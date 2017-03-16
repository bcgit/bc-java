package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

/**
 * Interface for stream cipher services.
 */
public interface TlsStreamCipherImpl
{
    /**
     * Set the key to be used by the stream cipher implementation supporting this service.
     *
     * @param key the stream cipher key.
     */
    void setKey(byte[] key) throws IOException;

    /**
     * Initialise the parameters for stream cipher.
     *
     * @param nonce the nonce for the stream cipher.
     * @throws IOException if the parameters are inappropriate.
     */
    void init(byte[] nonce) throws IOException;

    /**
     * Perform the cipher encryption/decryption returning the output in output.
     * <p>
     * Note: we have to use doFinal() here as it is the only way to guarantee output from the underlying cipher.
     * </p>
     * @param input array holding input data to the cipher.
     * @param inputOffset offset into input array data starts at.
     * @param inputLength length of the input data in the array.
     * @param output array to hold the cipher output.
     * @param outputOffset offset into output array to start saving output.
     * @return the amount of data written to output.
     * @throws IOException in case of failure.
     */
    int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset) throws IOException;
}
