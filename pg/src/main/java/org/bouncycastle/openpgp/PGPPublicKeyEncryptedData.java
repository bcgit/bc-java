package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.InputStream;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.SessionKeyDataDecryptorFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * A public key encrypted data object.
 */
public class PGPPublicKeyEncryptedData
    extends PGPEncryptedData
{

    PublicKeyEncSessionPacket keyData;

    PGPPublicKeyEncryptedData(
        PublicKeyEncSessionPacket keyData,
        InputStreamPacket encData)
    {
        super(encData);

        this.keyData = keyData;
    }

    private boolean confirmCheckSum(
        byte[] sessionInfo)
    {
        int check = 0;

        for (int i = 1; i != sessionInfo.length - 2; i++)
        {
            check += sessionInfo[i] & 0xff;
        }

        return (sessionInfo[sessionInfo.length - 2] == (byte)(check >> 8))
            && (sessionInfo[sessionInfo.length - 1] == (byte)(check));
    }

    /**
     * Return the keyID for the key used to encrypt the data.
     *
     * @return long
     */
    public long getKeyID()
    {
        return keyData.getKeyID();
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
        PublicKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        if (keyData.getVersion() == PublicKeyEncSessionPacket.VERSION_3)
        {
            byte[] plain = dataDecryptorFactory.recoverSessionData(keyData.getAlgorithm(), keyData.getEncSessionKey());
            // symmetric cipher algorithm is stored in first octet of session data
            return plain[0];
        }
        else if (keyData.getVersion() == PublicKeyEncSessionPacket.VERSION_6)
        {
            // PKESK v5 stores the cipher algorithm in the SEIPD v2 packet fields.
            return ((SymmetricEncIntegrityPacket) encData).getCipherAlgorithm();
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported packet version: " + keyData.getVersion());
        }
    }

    /**
     * Return the symmetric session key required to decrypt the data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data.
     * @return session key used to decrypt the data protected by this object
     * @throws PGPException if the session data cannot be recovered.
     */
    public PGPSessionKey getSessionKey(
        PublicKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getAlgorithm(), keyData.getEncSessionKey());
        if (!confirmCheckSum(sessionData))
        {
            throw new PGPKeyValidationException("key checksum failed");
        }

        return new PGPSessionKey(sessionData[0] & 0xff, Arrays.copyOfRange(sessionData, 1, sessionData.length - 2));
    }

    /**
     * Open an input stream which will provide the decrypted data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data and provide the stream.
     * @return the resulting input stream
     * @throws PGPException if the session data cannot be recovered or the stream cannot be created.
     */
    public InputStream getDataStream(
        PublicKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        return getDataStream(dataDecryptorFactory, getSessionKey(dataDecryptorFactory));
    }

    /**
     * @deprecated will be removed in 1.74, use PGPEncryptedDataList.extractSessionKeyEncryptedData() and then apply the dataDecryptorFactory.
     */
    public InputStream getDataStream(
        SessionKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        return getDataStream(dataDecryptorFactory, dataDecryptorFactory.getSessionKey());
    }

    /**
     * Open an input stream which will provide the decrypted data protected by this object.
     *
     * @param dataDecryptorFactory decryptor factory to use to recover the session data and provide the stream.
     * @param sessionKey           the session key for the stream.
     * @return the resulting input stream
     * @throws PGPException if the session data cannot be recovered or the stream cannot be created.
     */
    private InputStream getDataStream(
        PGPDataDecryptorFactory dataDecryptorFactory,
        PGPSessionKey sessionKey)
        throws PGPException
    {
        if (sessionKey.getAlgorithm() != SymmetricKeyAlgorithmTags.NULL)
        {
            try
            {
                // OpenPGP V5 style AEAD
                if (encData instanceof AEADEncDataPacket)
                {
                    AEADEncDataPacket aeadData = (AEADEncDataPacket)encData;

                    if (aeadData.getAlgorithm() != sessionKey.getAlgorithm())
                    {
                        throw new PGPException("session key and AEAD algorithm mismatch");
                    }

                    PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(aeadData, sessionKey);

                    BCPGInputStream encIn = encData.getInputStream();

                    encStream = new BCPGInputStream(dataDecryptor.getInputStream(encIn));
                }
                else
                {
                    boolean withIntegrityPacket = encData instanceof SymmetricEncIntegrityPacket;

                    PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(withIntegrityPacket, sessionKey.getAlgorithm(), sessionKey.getKey());

                    BCPGInputStream encIn = encData.getInputStream();

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

                    //
                    // some versions of PGP appear to produce 0 for the extra
                    // bytes rather than repeating the two previous bytes
                    //
                    /*
                     * Commented out in the light of the oracle attack.
                    if (iv[iv.length - 2] != (byte)v1 && v1 != 0)
                    {
                        throw new PGPDataValidationException("data check failed.");
                    }

                    if (iv[iv.length - 1] != (byte)v2 && v2 != 0)
                    {
                        throw new PGPDataValidationException("data check failed.");
                    }
                    */
                }

                return encStream;
            }
            catch (PGPException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PGPException("Exception starting decryption", e);
            }
        }
        else
        {
            return encData.getInputStream();
        }
    }

    public int getAlgorithm()
    {
        return keyData.getAlgorithm();
    }

    public int getVersion()
    {
        return keyData.getVersion();
    }
}
