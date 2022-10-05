package org.bouncycastle.openpgp;

import java.io.InputStream;

import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

/**
 * The basis of PGP encrypted data - encrypted data encrypted using a symmetric session key.
 */
public class PGPSessionKeyEncryptedData
    extends PGPSymmetricKeyEncryptedData
{
    private final PGPSessionKey sessionKey;

    PGPSessionKeyEncryptedData(InputStreamPacket encData)
    {
        super(encData);
        this.sessionKey = null;
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
