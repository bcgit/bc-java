package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

public interface PGPDataDecryptorFactory
{
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException;
}
