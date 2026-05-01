package org.bouncycastle.openpgp;

import java.io.InputStream;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataDecryptorFactory;

public class PGPSymmetricKeyEncryptedData
    extends PGPEncryptedData
{
    protected PGPSymmetricKeyEncryptedData(InputStreamPacket encData)
    {
        super(encData);
    }

    protected InputStream createDecryptionStream(PGPDataDecryptorFactory dataDecryptorFactory, PGPSessionKey sessionKey)
        throws PGPException
    {
        // OpenPGP v5
        if (encData instanceof AEADEncDataPacket)
        {
            AEADEncDataPacket aeadData = (AEADEncDataPacket)encData;

            if (aeadData.getAlgorithm() != sessionKey.getAlgorithm())
            {
                throw new PGPException("session key and AEAD algorithm mismatch");
            }

            PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(aeadData, sessionKey);
            InputStream encIn = getInputStream();

            return dataDecryptor.getInputStream(encIn);
        }
        else if (encData instanceof SymmetricEncIntegrityPacket)
        {
            SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket)encData;

            // OpenPGP v4 (SEIPD v1 with integrity protection)
            if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_1)
            {
                PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(true,
                    sessionKey.getAlgorithm(), sessionKey.getKey());
                return getDataStream(true, dataDecryptor);
            }

            // OpenPGP v6 (AEAD with SEIPD v2)
            else if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_2)
            {
                PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(seipd, sessionKey);
                return dataDecryptor.getInputStream(getInputStream());
            }

            // Unsupported
            else
            {
                throw new UnsupportedPacketVersionException("Unsupported SEIPD packet version: " + seipd.getVersion());
            }
        }
        // OpenPGP v3,v4 (SED without integrity protection)
        else
        {
            PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(false, sessionKey.getAlgorithm(), sessionKey.getKey());
            return getDataStream(false, dataDecryptor);
        }
    }

    private InputStream getDataStream(
        boolean withIntegrityPacket,
        PGPDataDecryptor dataDecryptor)
        throws PGPException
    {
        try
        {
            InputStream encIn = getInputStream();
            encIn.mark(dataDecryptor.getBlockSize() + 2); // iv + 2 octets checksum
            if (processSymmetricEncIntegrityPacketDataStream(withIntegrityPacket, dataDecryptor, encIn))
            {
                encIn.reset();
                throw new PGPDataValidationException("data check failed.");
            }

            return encStream;
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }
}
