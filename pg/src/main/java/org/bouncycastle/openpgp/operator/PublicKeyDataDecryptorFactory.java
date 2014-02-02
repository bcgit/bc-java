package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

public interface PublicKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData)
            throws PGPException;
}
