package org.bouncycastle.openpgp;

import java.io.InputStream;

import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
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
    }

    public int getVersion()
    {
        return keyData.getVersion();
    }

    public int getAlgorithm()
    {
        return keyData.getEncAlgorithm();
    }

    /**
     * Return the symmetric key algorithm required to decrypt the data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data.
     * @return the identifier of the {@link SymmetricKeyAlgorithmTags encryption algorithm} used to
     * encrypt this object.
     * @throws PGPException if the session data cannot be recovered.
     */
    public int getSymmetricAlgorithm(
        PBEDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        byte[] key = dataDecryptorFactory.makeKeyFromPassPhrase(keyData.getEncAlgorithm(), keyData.getS2K());
        byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getEncAlgorithm(), key, keyData.getSecKeyData());

        return sessionData[0];
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
        byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getEncAlgorithm(), key, keyData.getSecKeyData());

        return new PGPSessionKey(sessionData[0] & 0xff, Arrays.copyOfRange(sessionData, 1, sessionData.length));
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
