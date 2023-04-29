package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

/**
 * A decryptor factory for handling PGP session keys.
 */
public class BcSessionKeyDataDecryptorFactory
    implements SessionKeyDataDecryptorFactory
{
    private final PGPSessionKey sessionKey;

    public BcSessionKeyDataDecryptorFactory(PGPSessionKey sessionKey)
    {
        this.sessionKey = sessionKey;
    }

    @Override
    public PGPSessionKey getSessionKey()
    {
        return sessionKey;
    }

    // OpenPGP v4
    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }

    // OpenPGP v5
    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
        throws PGPException
    {
        return BcAEADUtil.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
    }

    // OpenPGP v6
    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
            throws PGPException
    {
        return BcAEADUtil.createOpenPgpV6DataDecryptor(seipd, sessionKey);
    }

}
