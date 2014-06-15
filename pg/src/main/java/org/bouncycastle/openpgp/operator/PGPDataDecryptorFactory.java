package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;

/**
 * Base interface of factories for {@link PGPDataDecryptor}.
 */
public interface PGPDataDecryptorFactory
{
    /**
     * Constructs a data decryptor.
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
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException;
}
