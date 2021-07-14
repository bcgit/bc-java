package org.bouncycastle.tls.crypto;

import java.io.IOException;

/**
 * Base interface for an encryptor.
 */
public interface TlsEncryptor
{
    /**
     * Encrypt data from the passed in input array.
     *
     * @param input byte array containing the input data.
     * @param inOff offset into input where the data starts.
     * @param length the length of the data to encrypt.
     * @return the encrypted data.
     * @throws IOException in case of a processing error.
     */
    byte[] encrypt(byte[] input, int inOff, int length)
        throws IOException;
}
