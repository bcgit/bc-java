package org.bouncycastle.openpgp.operator;

import java.math.BigInteger;

import org.bouncycastle.openpgp.PGPException;

public interface PublicKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    public byte[] recoverSessionData(int keyAlgorithm, BigInteger[] secKeyData)
            throws PGPException;
}
