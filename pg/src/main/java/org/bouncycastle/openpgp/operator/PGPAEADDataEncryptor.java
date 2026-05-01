package org.bouncycastle.openpgp.operator;


/**
 * A data encryptor, using AEAD.
 * There are two different flavours of AEAD encryption used with OpenPGP.
 * LibrePGP (v5) AEAD is slightly different from RFC9580 (v6) AEAD.
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
