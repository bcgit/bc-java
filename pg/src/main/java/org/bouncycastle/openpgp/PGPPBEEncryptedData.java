package org.bouncycastle.openpgp;

import java.io.InputStream;

import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.util.Arrays;

/**
 * A password based encryption object.
 * <p>
 * PBE encrypted data objects can be {@link #getDataStream(PBEDataDecryptorFactory) decrypted }
 * using a {@link PBEDataDecryptorFactory}.
 * </p>
 */
public class PGPPBEEncryptedData
        extends PGPSymmetricKeyEncryptedData
{
    SymmetricKeyEncSessionPacket keyData;

    /**
     * Construct a PBE encrypted data object.
     *
     * @param keyData the PBE key data packet associated with the encrypted data in the PGP object
     *                stream.
     * @param encData the encrypted data.
     */
    PGPPBEEncryptedData(
            SymmetricKeyEncSessionPacket keyData,
            InputStreamPacket encData)
    {
        super(encData);

        this.keyData = keyData;

        enforceConstraints(keyData, encData);
    }

    private static void enforceConstraints(SymmetricKeyEncSessionPacket keyData, InputStreamPacket encData)
    {
        switch (keyData.getVersion())
        {
            case SymmetricKeyEncSessionPacket.VERSION_4:
                if (encData instanceof SymmetricEncDataPacket)
                {
                    return;
                }

                if (encData instanceof SymmetricEncIntegrityPacket)
                {
                    SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket) encData;
                    if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_1)
                    {
                        return;
                    }

                    // V2 SEIPD cannot be preceded by V4 SKESK
                    throw new IllegalArgumentException("Version 4 SKESK cannot precede SEIPD of version " + seipd.getVersion());
                }

            case SymmetricKeyEncSessionPacket.VERSION_5:
                // https://www.ietf.org/archive/id/draft-koch-openpgp-2015-rfc4880bis-01.html does not state any constraints
                break;

            case SymmetricKeyEncSessionPacket.VERSION_6:
                // V6 SKESK MUST be followed by v2 SEIPD
                if (!(encData instanceof SymmetricEncIntegrityPacket))
                {
                    throw new IllegalArgumentException("Version 6 SKESK MUST be followed only by SEIPD version 2");
                }

                SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket) encData;
                if (seipd.getVersion() != SymmetricEncIntegrityPacket.VERSION_2)
                {
                    throw new IllegalArgumentException("Version 6 SKESK MUST be followed only by SEIPD version 2");
                }
        }
        if (encData instanceof SymmetricEncDataPacket)
        {
            if (keyData.getVersion() != SymmetricKeyEncSessionPacket.VERSION_4)
            {
                throw new IllegalArgumentException("Version of SKESK packet preceding a SED packet can only be 4.");
            }
        }

        if (encData instanceof SymmetricEncIntegrityPacket)
        {
            SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket) encData;
            if (keyData.getVersion() == SymmetricKeyEncSessionPacket.VERSION_4 &&
                    seipd.getVersion() != SymmetricEncIntegrityPacket.VERSION_1)
            {
                throw new IllegalArgumentException("Version 4 SKESK can only precede version 1 SEIPD.");
            }

            if (keyData.getVersion() == SymmetricKeyEncSessionPacket.VERSION_6 &&
                    seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_1)
            {
                throw new IllegalArgumentException("Version 6 SKESK packet MUST NOT precede a V1 SEIPD packet.");
            }
        }
    }

    public int getVersion()
    {
        return keyData.getVersion();
    }

    /**
     * Symmetric-key algorithm used by this object to protect the session key
     * ({@link #getSymmetricAlgorithm(PBEDataDecryptorFactory)} with.
     *
     * @return password-based encryption algorithm identifier ({@link SymmetricKeyAlgorithmTags})
     */
    public int getAlgorithm()
    {
        return keyData.getEncAlgorithm();
    }

    /**
     * Return the symmetric key algorithm required to decrypt the data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data.
     * @return session key algorithm identifier ({@link SymmetricKeyAlgorithmTags})
     * @throws PGPException if the session data cannot be recovered.
     */
    public int getSymmetricAlgorithm(
            PBEDataDecryptorFactory dataDecryptorFactory)
            throws PGPException
    {
        if (keyData.getVersion() == SymmetricKeyEncSessionPacket.VERSION_4)
        {
            // SKESK v4 stores cipher algorithm inside the encrypted session data
            byte[] key = dataDecryptorFactory.makeKeyFromPassPhrase(keyData.getEncAlgorithm(), keyData.getS2K());
            byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getEncAlgorithm(), key, keyData.getSecKeyData());

            return sessionData[0];
        }
        else if (keyData.getVersion() == SymmetricKeyEncSessionPacket.VERSION_5)
        {
            return keyData.getEncAlgorithm();
        }
        else // keyData.getVersion() == 5+
        {
            // SKESK v6 stores the cipher algorithm in the SEIPD v2 packet fields.
            return ((SymmetricEncIntegrityPacket) encData).getCipherAlgorithm();
        }
    }

    /**
     * Return the symmetric session key required to decrypt the data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory used to recover the session data.
     * @return session key
     * @throws PGPException if the session data cannot be recovered
     */
    public PGPSessionKey getSessionKey(PBEDataDecryptorFactory dataDecryptorFactory)
            throws PGPException
    {
        byte[] key = dataDecryptorFactory.makeKeyFromPassPhrase(keyData.getEncAlgorithm(), keyData.getS2K());

        int version = getVersion();
        if (version == SymmetricKeyEncSessionPacket.VERSION_4)
        {
            byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getEncAlgorithm(), key, keyData.getSecKeyData());
            int sessionKeyAlg = sessionData[0] & 0xff;
            byte[] sessionKey = Arrays.copyOfRange(sessionData, 1, sessionData.length);
            return new PGPSessionKey(sessionKeyAlg, sessionKey);
        }
        else if (version == SymmetricKeyEncSessionPacket.VERSION_5 || version == SymmetricKeyEncSessionPacket.VERSION_6)
        {
            int sessionKeyAlg = getSymmetricAlgorithm(dataDecryptorFactory);
            byte[] sessionKey = dataDecryptorFactory.recoverAEADEncryptedSessionData(keyData, key);
            return new PGPSessionKey(sessionKeyAlg, sessionKey);
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported packet version: " + version);
        }
    }

    /**
     * Open an input stream which will provide the decrypted data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data and provide
     *                             the stream.
     * @return the resulting decrypted input stream, probably containing a sequence of PGP data
     * objects.
     * @throws PGPException if the session data cannot be recovered or the stream cannot be created.
     */
    public InputStream getDataStream(
            PBEDataDecryptorFactory dataDecryptorFactory)
            throws PGPException
    {
        try
        {
            PGPSessionKey sessionKey = getSessionKey(dataDecryptorFactory);
            encStream = createDecryptionStream(dataDecryptorFactory, sessionKey);
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

    /**
     * @deprecated will be removed in 1.74, use PGPEncryptedDataList.extractSessionKeyEncryptedData() and then apply the dataDecryptorFactory.
     */
    public InputStream getDataStream(
            SessionKeyDataDecryptorFactory dataDecryptorFactory)
            throws PGPException
    {
        try
        {
            PGPSessionKey sessionKey = dataDecryptorFactory.getSessionKey();

            encStream = createDecryptionStream(dataDecryptorFactory, sessionKey);

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
