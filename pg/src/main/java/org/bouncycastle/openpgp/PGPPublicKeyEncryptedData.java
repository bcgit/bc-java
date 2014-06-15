package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.InputStream;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.util.io.TeeInputStream;

/**
 * A public key encrypted data object.
 */
public class PGPPublicKeyEncryptedData
    extends PGPEncryptedData
{
    PublicKeyEncSessionPacket        keyData;

    PGPPublicKeyEncryptedData(
        PublicKeyEncSessionPacket    keyData,
        InputStreamPacket            encData)
    {
        super(encData);

        this.keyData = keyData;
    }

    private boolean confirmCheckSum(
        byte[]    sessionInfo)
    {
        int    check = 0;

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
     *         encrypt this object.
     * @throws PGPException if the session data cannot be recovered.
     */
    public int getSymmetricAlgorithm(
        PublicKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        byte[] plain = dataDecryptorFactory.recoverSessionData(keyData.getAlgorithm(), keyData.getEncSessionKey());

        return plain[0];
    }

    /**
     * Open an input stream which will provide the decrypted data protected by this object.
     *
     * @param dataDecryptorFactory  decryptor factory to use to recover the session data and provide the stream.
     * @return  the resulting input stream
     * @throws PGPException  if the session data cannot be recovered or the stream cannot be created.
     */
    public InputStream getDataStream(
        PublicKeyDataDecryptorFactory dataDecryptorFactory)
        throws PGPException
    {
        byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getAlgorithm(), keyData.getEncSessionKey());

        if (!confirmCheckSum(sessionData))
        {
            throw new PGPKeyValidationException("key checksum failed");
        }

        if (sessionData[0] != SymmetricKeyAlgorithmTags.NULL)
        {
            try
            {
                boolean      withIntegrityPacket = encData instanceof SymmetricEncIntegrityPacket;
                byte[]       sessionKey = new byte[sessionData.length - 3];

                System.arraycopy(sessionData, 1, sessionKey, 0, sessionKey.length);

                PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(withIntegrityPacket, sessionData[0] & 0xff, sessionKey);

                encStream = new BCPGInputStream(dataDecryptor.getInputStream(encData.getInputStream()));

                if (withIntegrityPacket)
                {
                    truncStream = new TruncatedStream(encStream);

                    integrityCalculator = dataDecryptor.getIntegrityCalculator();

                    encStream = new TeeInputStream(truncStream, integrityCalculator.getOutputStream());
                }

                byte[] iv = new byte[dataDecryptor.getBlockSize()];

                for (int i = 0; i != iv.length; i++)
                {
                    int    ch = encStream.read();

                    if (ch < 0)
                    {
                        throw new EOFException("unexpected end of stream.");
                    }

                    iv[i] = (byte)ch;
                }

                int    v1 = encStream.read();
                int    v2 = encStream.read();

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
}
