package org.bouncycastle.openpgp.operator;

/**
 * A data encryptor, using AEAD
 * <p>
 * {@link PGPAEADDataEncryptor} instances are generally not constructed directly, but obtained from a
 * {@link PGPDataEncryptorBuilder}.
 * </p>
 */
public interface PGPAEADDataEncryptor
    extends PGPDataEncryptor
{
    int getAEADAlgorithm();

    int getChunkSize();

    byte[] getIV();
}
