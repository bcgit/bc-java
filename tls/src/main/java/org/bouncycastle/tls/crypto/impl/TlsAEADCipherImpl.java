package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

/**
 * Base interface for services supporting AEAD encryption/decryption.
 */
public interface TlsAEADCipherImpl
{
    /**
     * Set the key to be used by the AEAD cipher implementation supporting this service.
     *
     * @param key the AEAD cipher key.
     */
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

    /**
     * Return the maximum size of the output for input of inputLength bytes.
     *
     * @param inputLength the length (in bytes) of the proposed input.
     * @return the maximum size of the output.
     */
    int getOutputSize(int inputLength);

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
