package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.InputStream;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * A password based encryption object.
 * <p>
 * PBE encrypted data objects can be {@link #getDataStream(PBEDataDecryptorFactory) decrypted }
 * using a {@link PBEDataDecryptorFactory}.
 * </p>
 */
public class PGPPBEEncryptedData
    extends PGPEncryptedData
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

            if (encData instanceof AEADEncDataPacket)
            {
                AEADEncDataPacket aeadData = (AEADEncDataPacket)encData;

                if (aeadData.getAlgorithm() != sessionKey.getAlgorithm())
                {
                    throw new PGPException("session key and AEAD algorithm mismatch");
                }

                PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(aeadData.getAEADAlgorithm(), aeadData.getIV(), aeadData.getChunkSize(), sessionKey.getAlgorithm(), sessionKey.getKey());

                BCPGInputStream encIn = encData.getInputStream();

                encStream = new BCPGInputStream(dataDecryptor.getInputStream(encIn));
            }
            else
            {
                boolean withIntegrityPacket = encData instanceof SymmetricEncIntegrityPacket;
                PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(withIntegrityPacket, sessionKey.getAlgorithm(), sessionKey.getKey());

                encStream =  getDataStream(withIntegrityPacket, dataDecryptor);
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

    public InputStream getDataStream(
        SessionKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        try
        {
            PGPSessionKey sessionKey = dataDecryptorFactory.getSessionKey();
            boolean withIntegrityPacket = encData instanceof SymmetricEncIntegrityPacket;
            PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(withIntegrityPacket, sessionKey.getAlgorithm(), sessionKey.getKey());

            return getDataStream(withIntegrityPacket, dataDecryptor);
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

    private InputStream getDataStream(
        boolean withIntegrityPacket,
        PGPDataDecryptor dataDecryptor)
        throws PGPException
    {
        try
        {
            BCPGInputStream encIn = encData.getInputStream();
            encIn.mark(dataDecryptor.getBlockSize() + 2); // iv + 2 octets checksum

            encStream = new BCPGInputStream(dataDecryptor.getInputStream(encIn));

            if (withIntegrityPacket)
            {
                truncStream = new TruncatedStream(encStream);

                integrityCalculator = dataDecryptor.getIntegrityCalculator();

                encStream = new TeeInputStream(truncStream, integrityCalculator.getOutputStream());
            }

            byte[] iv = new byte[dataDecryptor.getBlockSize()];
            for (int i = 0; i != iv.length; i++)
            {
                int ch = encStream.read();

                if (ch < 0)
                {
                    throw new EOFException("unexpected end of stream.");
                }

                iv[i] = (byte)ch;
            }

            int v1 = encStream.read();
            int v2 = encStream.read();

            if (v1 < 0 || v2 < 0)
            {
                throw new EOFException("unexpected end of stream.");
            }


            // Note: the oracle attack on "quick check" bytes is not deemed
            // a security risk for PBE (see PGPPublicKeyEncryptedData)

            boolean repeatCheckPassed = iv[iv.length - 2] == (byte)v1
                && iv[iv.length - 1] == (byte)v2;

            // Note: some versions of PGP appear to produce 0 for the extra
            // bytes rather than repeating the two previous bytes
            boolean zeroesCheckPassed = v1 == 0 && v2 == 0;

            if (!repeatCheckPassed && !zeroesCheckPassed)
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

    public int getVersion()
    {
        return keyData.getVersion();
    }

    public int getAlgorithm()
    {
        return keyData.getEncAlgorithm();
    }
}
