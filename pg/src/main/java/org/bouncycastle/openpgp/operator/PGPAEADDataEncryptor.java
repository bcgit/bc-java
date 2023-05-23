package org.bouncycastle.openpgp.operator;


/**
 * A data encryptor, using AEAD.
 * There are two different flavours of AEAD encryption used with OpenPGP.
 * OpenPGP v5 AEAD is slightly different from v6 AEAD.
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
