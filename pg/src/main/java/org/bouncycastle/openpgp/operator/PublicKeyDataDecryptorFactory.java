package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPException;

public interface PublicKeyDataDecryptorFactory
    extends PGPDataDecryptorFactory
{
    byte[] recoverSessionData(PublicKeyEncSessionPacket pkesk, InputStreamPacket encData)
            throws PGPException;

    /**
     * @deprecated use {@link #recoverSessionData(PublicKeyEncSessionPacket, InputStreamPacket)} (PublicKeyEncSessionPacket, InputStreamPacket)} instead.
     * @param keyAlgorithm public key algorithm
     * @param secKeyData encrypted session key data
     * @param pkeskVersion version of the PKESK packet
     * @return
     * @throws PGPException
     */
    byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion)
            throws PGPException;

}
