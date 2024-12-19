package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;

/**
 * An encryption method that can be applied to encrypt data in a {@link PGPEncryptedDataGenerator}.
 */
public interface PGPKeyEncryptionMethodGenerator
{

    ContainedPacket generate(PGPDataEncryptorBuilder dataEncryptorBuilder, byte[] sessionKey)
        throws PGPException;
}
