package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPAEADFlavour;

/**
 * A data encryptor, using AEAD.
 * There are two different flavours of AEAD encryption used with OpenPGP. See {@link PGPAEADFlavour} for more details.
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

    boolean isV5StyleAEAD();
}
