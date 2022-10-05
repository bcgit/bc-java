package org.bouncycastle.openpgp;

import java.io.InputStream;

import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

public class PGPSessionKeyEncryptedData
    extends PGPSymmetricEncryptedData
{
    private final PGPSessionKey sessionKey;

    PGPSessionKeyEncryptedData(PGPSessionKey sessionKey, InputStreamPacket encData)
    {
        super(encData);
        this.sessionKey = sessionKey;
    }

    @Override
    public int getAlgorithm()
    {
        return sessionKey.getAlgorithm();
    }

    public PGPSessionKey getSessionKey()
    {
        return sessionKey;
    }

    public InputStream getDataStream(
        SessionKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        encStream = createDecryptionStream(dataDecryptorFactory, sessionKey);

        return encStream;
    }
}
