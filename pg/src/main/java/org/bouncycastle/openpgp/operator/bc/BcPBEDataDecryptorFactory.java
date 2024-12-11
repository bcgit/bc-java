package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;

/**
 * A {@link PBEDataDecryptorFactory} for handling PBE decryption operations using the Bouncy Castle
 * lightweight API to implement cryptographic primitives.
 */
public class BcPBEDataDecryptorFactory
    extends PBEDataDecryptorFactory
{
    /**
     * Base constructor.
     *
     * @param pass               the passphrase to use as the primary source of key material.
     * @param calculatorProvider a digest calculator provider to provide calculators to support the key generation calculation required.
     */
    public BcPBEDataDecryptorFactory(char[] pass, PGPDigestCalculatorProvider calculatorProvider)
    {
        super(pass, calculatorProvider);
    }

    /**
     * Recover the session key from a version 4 SKESK packet used in OpenPGP v4.
     *
     * @param keyAlgorithm the {@link SymmetricKeyAlgorithmTags encryption algorithm} used to
     *                     encrypt the session data.
     * @param key          the key bytes for the encryption algorithm.
     * @param secKeyData   the encrypted session data to decrypt.
     * @return session key
     * @throws PGPException
     */
    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] secKeyData)
        throws PGPException
    {
        try
        {
            if (secKeyData != null && secKeyData.length > 0)
            {
                BlockCipher engine = BcImplProvider.createBlockCipher(keyAlgorithm);
                return BcUtil.processBufferedBlockCipher(false, engine, key, new byte[engine.getBlockSize()], secKeyData, 0, secKeyData.length);
            }
            else
            {
                byte[] keyBytes = new byte[key.length + 1];

                keyBytes[0] = (byte)keyAlgorithm;
                System.arraycopy(key, 0, keyBytes, 1, key.length);

                return keyBytes;
            }
        }
        catch (Exception e)
        {
            throw new PGPException("Exception recovering session info", e);
        }
    }

    @Override
    public byte[] recoverAEADEncryptedSessionData(SymmetricKeyEncSessionPacket keyData, byte[] ikm)
        throws PGPException
    {
        if (keyData.getVersion() < SymmetricKeyEncSessionPacket.VERSION_5)
        {
            throw new PGPException("SKESK packet MUST be version 5 or later.");
        }

        byte[] hkdfInfo = keyData.getAAData(); // Between v5 and v6, these bytes differ

        byte[] kek;
        if (keyData.getVersion() == SymmetricKeyEncSessionPacket.VERSION_5)
        {
            kek = ikm;
        }
        else if (keyData.getVersion() == SymmetricKeyEncSessionPacket.VERSION_6)
        {
            // HKDF
            // secretKey := HKDF_sha256(ikm, hkdfInfo).generate()
            int kekLen = SymmetricKeyUtils.getKeyLengthInOctets(keyData.getEncAlgorithm());
            kek = BcAEADUtil.generateHKDFBytes(ikm, null, hkdfInfo, kekLen);
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported SKESK packet version encountered: " + keyData.getVersion());
        }

        // AEAD
        // sessionData := AEAD(secretKey).decrypt(encSessionKey || authTag)
        byte[] data = Arrays.concatenate(keyData.getSecKeyData(), keyData.getAuthTag());
        return BcAEADUtil.processAEADData(false, keyData.getEncAlgorithm(), keyData.getAeadAlgorithm(), kek,
            keyData.getIv(), keyData.getAAData(), data, 0, data.length,
            BcAEADUtil.RecoverAEADEncryptedSessionDataErrorMessage);
    }

    // OpenPGP v4
    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
        throws PGPException
    {
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }

    // OpenPGP v5
    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
        throws PGPException
    {
        return BcAEADUtil.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
    }

    // OpenPGP v6
    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
        throws PGPException
    {
        return BcAEADUtil.createOpenPgpV6DataDecryptor(seipd, sessionKey);
    }
}