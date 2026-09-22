package org.bouncycastle.openpgp;

import java.io.InputStream;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;

/**
 * The basis of PGP encrypted data - encrypted data encrypted using a symmetric session key.
 */
public class PGPSessionKeyEncryptedData
    extends PGPSymmetricKeyEncryptedData
{
    private final boolean passwordDerivedSessionKey;

    PGPSessionKeyEncryptedData(InputStreamPacket encData)
    {
        this(encData, false);
    }

    PGPSessionKeyEncryptedData(InputStreamPacket encData, boolean passwordDerivedSessionKey)
    {
        super(encData);

        this.passwordDerivedSessionKey = passwordDerivedSessionKey;
    }

    @Override
    public int getAlgorithm()
    {
        if (encData instanceof AEADEncDataPacket)
        {
            AEADEncDataPacket aeadData = (AEADEncDataPacket)encData;

            return aeadData.getAlgorithm();
        }
        else
        {
            return -1; // unknown
        }
    }

    @Override
    public int getVersion()
    {
        if (encData instanceof AEADEncDataPacket)
        {
            AEADEncDataPacket aeadData = (AEADEncDataPacket)encData;

            return aeadData.getVersion();
        }
        else if (encData instanceof SymmetricEncIntegrityPacket)
        {
            SymmetricEncIntegrityPacket symIntData = (SymmetricEncIntegrityPacket)encData;

            return symIntData.getVersion();
        }
        else
        {
            return -1;    // unmarked
        }
    }

    public InputStream getDataStream(
        SessionKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        encStream = createDecryptionStream(dataDecryptorFactory, dataDecryptorFactory.getSessionKey());

        return encStream;
    }

    // Only a session key the caller states came from a password may be quick checked - for one recovered from a public key operation the check is the Mister-Zuccherato oracle, and integrity is enforced by the SEIPD v1 MDC.
    @Override
    protected boolean useQuickCheck()
    {
        return passwordDerivedSessionKey;
    }
}
