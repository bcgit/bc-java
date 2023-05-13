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
     * This method defaults to using OpenPGP v5.
     * If you want to be compatible to OpenPGP v6, use {@link #setWithV6AEAD(int, int)} instead.
     * The chunkSize is used as a power of two, result in blocks (1 &lt;&lt; chunkSize) containing data
     * with an extra 16 bytes for the tag. The minimum chunkSize is 6.
     *
     * @param aeadAlgorithm the AEAD mode to use.
     * @param chunkSize the size of the chunks to be processed with each nonce.
     * @deprecated use {@link #setWithV5AEAD(int, int)} or {@link #setWithV6AEAD(int, int)} instead.
     */
    PGPDataEncryptorBuilder setWithAEAD(int aeadAlgorithm, int chunkSize);

    /**
     * Sets whether the resulting encrypted data will be protected using an OpenPGP V5 compatible AEAD mode.
     * RFC4880bis10 defines the AEAD/OCB Encrypted Data packet.
     * The session key is retrieved from symmetrically encrypted session key (SKESK) packets of
     * {@link org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket#VERSION_5 version 5}, or
     * public-key encrypted session key (PKESK) packets of
     * {@link org.bouncycastle.bcpg.PublicKeyEncSessionPacket#VERSION_3 version 3}.
     * This method of using AEAD in OpenPGP does not follow consensus of the OpenPGP working group.
     * The chunkSize is used as a power of two, result in blocks (1 &lt;&lt; chunkSize) containing data
     * with an extra 16 bytes for the tag. The minimum chunkSize is 6.
     *
     * @param aeadAlgorithm the AEAD mode to use.
     * @param chunkSize the size of the chunks to be processed with each nonce.
     */
    PGPDataEncryptorBuilder setWithV5AEAD(int aeadAlgorithm, int chunkSize);


    /**
     * Sets whether the resulting encrypted data will be protected using an OpenPGP v6 compatible AEAD mode.
     * The OpenPGP working group defines AEAD throughout the crypto-refresh document using a symmetrically
     * encrypted integrity-protected data (SEIPD) packet of
     * {@link org.bouncycastle.bcpg.SymmetricEncIntegrityPacket#VERSION_2 version 2}.
     * The session key is retrieved from symmetrically encrypted session key (SKESK) packets of
     * {@link org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket#VERSION_6 version 6}, or
     * public-key encrypted session key (PKESK) packets of
     * {@link org.bouncycastle.bcpg.PublicKeyEncSessionPacket#VERSION_6 version 6}.
     * The chunkSize is used as a power of two, result in blocks (1 &lt;&lt; chunkSize) containing data
     * with an extra 16 bytes for the tag. The minimum chunkSize is 6.
     *
     * @param aeadAlgorithm the AEAD mode to use.
     * @param chunkSize the size of the chunks to be processed with each nonce.
     */
    PGPDataEncryptorBuilder setWithV6AEAD(int aeadAlgorithm, int chunkSize);
}
