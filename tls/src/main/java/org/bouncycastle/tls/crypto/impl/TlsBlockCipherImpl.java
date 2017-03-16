package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;

/**
 * Interface for block cipher services.
 */
public interface TlsBlockCipherImpl
{
    /**
     * Set the key to be used by the block cipher implementation supporting this service.
     *
     * @param key the block cipher key.
     */
    void setKey(byte[] key) throws IOException;

    /**
     * Initialise the parameters for operator.
     *
     * @param iv the initialization vector.
     * @throws IOException if the parameters are inappropriate.
     */
    void init(byte[] iv) throws IOException;

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

    /**
     * Return the blocksize (in bytes) of the underlying block cipher.
     *
     * @return the cipher's blocksize.
     */
    int getBlockSize();
}
