package org.bouncycastle.openssl;

/**
 * Base interface for decryption operations.
 */
public interface PEMDecryptor
{
    /**
     * Decrypt the passed in data using the associated IV and the decryptor's key state.
     *
     * @param data the encrypted data
     * @param iv the initialisation vector associated with the decryption.
     * @return the decrypted data.
     * @throws PEMException in the event of an issue.
     */
    byte[] decrypt(byte[] data, byte[] iv)
        throws PEMException;
}
