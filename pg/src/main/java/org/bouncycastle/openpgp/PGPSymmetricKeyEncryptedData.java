package org.bouncycastle.openpgp;

import java.io.EOFException;
import java.io.InputStream;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDataDecryptorFactory;
import org.bouncycastle.util.io.TeeInputStream;

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

            PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(
                    aeadData, sessionKey);
            BCPGInputStream encIn = encData.getInputStream();

            return new BCPGInputStream(dataDecryptor.getInputStream(encIn));
        }
        else if (encData instanceof SymmetricEncIntegrityPacket)
        {
            SymmetricEncIntegrityPacket seipd = (SymmetricEncIntegrityPacket) encData;

            // OpenPGP v4 (SEIPD v1 with integrity protection)
            if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_1)
            {
                PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(true, sessionKey.getAlgorithm(), sessionKey.getKey());
                return getDataStream(true, dataDecryptor);
            }

            // OpenPGP v6 (AEAD with SEIPD v2)
            else if (seipd.getVersion() == SymmetricEncIntegrityPacket.VERSION_2)
            {
                PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(seipd, sessionKey);
                return new BCPGInputStream(dataDecryptor.getInputStream(encData.getInputStream()));
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
}
