package org.bouncycastle.openpgp.operator;

import java.io.InputStream;

/**
 * A decryptor that wraps a stream of PGP encrypted data to decrypt, and optionally integrity check,
 * the data.
 */
public interface PGPDataDecryptor
{
    /**
     * Wraps an encrypted data stream with a stream that will return the decrypted data.
     *
     * @param in the encrypted data.
     * @return a decrypting stream.
     */
    InputStream getInputStream(InputStream in);

    /**
     * Obtains the block size of the encryption algorithm used in this decryptor.
     *
     * @return the block size of the cipher in bytes.
     */
    int getBlockSize();

    /**
     * Obtains the digest calculator used to verify the integrity check.
     */
    PGPDigestCalculator getIntegrityCalculator();
}
