package org.bouncycastle.openpgp.operator;

import java.security.SecureRandom;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;

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

    int getAeadAlgorithm();

    int getChunkSize();

    boolean isV5StyleAEAD();

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

    /**
     * Sets whether or not the resulting encrypted data will be protected using an integrity packet.
     *
     * @param withIntegrityPacket true if an integrity packet is to be included, false otherwise.
     * @return the current builder.
     */
    PGPDataEncryptorBuilder setWithIntegrityPacket(boolean withIntegrityPacket);

    /**
     * Sets whether the resulting encrypted data will be protected using an AEAD mode.
     *
     * The chunkSize is used as a power of two, result in blocks (1 &lt;&lt; chunkSize) containing data
     * with an extra 16 bytes for the tag. The minimum chunkSize is 6.
     *
     * @param aeadAlgorithm the AEAD mode to use.
     * @param chunkSize the size of the chunks to be processed with each nonce.
     * @return the current builder
     */
    PGPDataEncryptorBuilder setWithAEAD(int aeadAlgorithm, int chunkSize);

    /**
     * Specify we are using V5 AEAD.
     *
     * @return the current builder
     */
    PGPDataEncryptorBuilder setUseV5AEAD();

    /**
     * Specify we are using V6 AEAD.
     *
     * @return the current builder
     */
    PGPDataEncryptorBuilder setUseV6AEAD();
}
