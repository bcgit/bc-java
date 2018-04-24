package org.bouncycastle.openpgp.operator;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;

/**
 * A builder for {@link PGPDataEncryptor} instances, which can be used to encrypt data objects.
 */
public interface PGPDataEncryptorBuilder
{
    /**
     * The encryption algorithm used by data encryptors created by this builder.
     *
     * @return one of the {@link SymmetricKeyAlgorithmTags symmetric encryption algorithms}.
     */
    int getAlgorithm();

    /**
     * Builds a data encryptor using the algorithm configured for this builder.
     *
     * @param keyBytes the bytes of the key to use for the cipher.
     * @return a data encryptor with an initialised cipher.
     * @throws PGPException if an error occurs initialising the configured encryption.
     */
    PGPDataEncryptor build(byte[] keyBytes)
        throws PGPException;

    /**
     * Gets the SecureRandom instance used by this builder.
     * <p>
     * If a SecureRandom has not been explicitly configured, a default {@link SecureRandom} is
     * constructed and retained by the this builder.</p>
     */
    SecureRandom getSecureRandom();
}
