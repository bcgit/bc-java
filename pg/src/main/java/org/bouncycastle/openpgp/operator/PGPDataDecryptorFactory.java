package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;

/**
 * Base interface of factories for {@link PGPDataDecryptor}.
 */
public interface PGPDataDecryptorFactory
{
    /**
     * Constructs a data decryptor for {@link org.bouncycastle.bcpg.SymmetricEncDataPacket SED} or
     * {@link SymmetricEncIntegrityPacket#VERSION_1 v1 SEIPD} packets.
     *
     * @param withIntegrityPacket <code>true</code> if the packet to be decrypted has integrity
     *            checking enabled.
     * @param encAlgorithm the identifier of the {@link SymmetricKeyAlgorithmTags encryption
     *            algorithm} to decrypt with.
     * @param key the bytes of the key for the cipher.
     * @return a data decryptor that can decrypt (and verify) streams of encrypted data.
     * @throws PGPException if an error occurs initialising the decryption and integrity checking
     *             functions.
     */
    PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException;

    /**
     * Constructs a data decryptor for {@link AEADEncDataPacket AEAD Encrypted Data} packets.
     * This method is used with OpenPGP v5 AEAD.
     *
     * @param aeadEncDataPacket AEAD encrypted data packet
     * @param sessionKey decrypted session key
     * @return a data decryptor that can decrypt (and verify) streams of encrypted data.
     * @throws PGPException if an error occurs initialising the decryption and integrity checking
     *             functions.
     */
    PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
        throws PGPException;

    /**
     * Constructs a data decryptor for {@link SymmetricEncIntegrityPacket#VERSION_2 v2 SEIPD} packets.
     * This method is used with OpenPGP v6 AEAD.
     *
     * @param seipd version 2 symmetrically encrypted integrity-protected data packet using AEAD.
     * @param sessionKey decrypted session key
     * @return a data decryptor that can decrypt (and verify) streams of encrypted data.
     * @throws PGPException if an error occurs initialising the decryption and integrity checking
     *             functions.
     */
    PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
        throws PGPException;
}
