package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;

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
     * @param pass  the passphrase to use as the primary source of key material.
     * @param calculatorProvider   a digest calculator provider to provide calculators to support the key generation calculation required.
     */
    public BcPBEDataDecryptorFactory(char[] pass, BcPGPDigestCalculatorProvider calculatorProvider)
    {
        super(pass, calculatorProvider);
    }

    /**
     * Recover the session key from a version 4 SKESK packet used in OpenPGP v4.
     *
     * @param keyAlgorithm the {@link SymmetricKeyAlgorithmTags encryption algorithm} used to
     *            encrypt the session data.
     * @param key the key bytes for the encryption algorithm.
     * @param secKeyData the encrypted session data to decrypt.
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
                BufferedBlockCipher cipher = BcUtil.createSymmetricKeyWrapper(false, engine, key, new byte[engine.getBlockSize()]);

                byte[] out = new byte[secKeyData.length];

                int len = cipher.processBytes(secKeyData, 0, secKeyData.length, out, 0);

                len += cipher.doFinal(out, len);

                return out;
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
        int kekLen = SymmetricKeyUtils.getKeyLengthInOctets(keyData.getEncAlgorithm());
        byte[] kek = new byte[kekLen];

        // HKDF
        // secretKey := HKDF_sha256(ikm, hkdfInfo).generate()
        HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());
        hkdfGen.init(new HKDFParameters(ikm, null, hkdfInfo));
        hkdfGen.generateBytes(kek, 0, kek.length);
        final KeyParameter secretKey = new KeyParameter(kek);

        // AEAD
        AEADBlockCipher aead = BcAEADUtil.createAEADCipher(keyData.getEncAlgorithm(), keyData.getAeadAlgorithm());
        int aeadMacLen = 128;
        byte[] authTag = keyData.getAuthTag();
        byte[] aeadIv = keyData.getIv();
        byte[] encSessionKey = keyData.getSecKeyData();

        // sessionData := AEAD(secretKey).decrypt(encSessionKey || authTag)
        AEADParameters parameters = new AEADParameters(secretKey,
                aeadMacLen, aeadIv, keyData.getAAData());
        aead.init(false, parameters);
        int sessionKeyLen = aead.getOutputSize(encSessionKey.length + authTag.length);
        byte[] sessionData = new byte[sessionKeyLen];
        int dataLen = aead.processBytes(encSessionKey, 0, encSessionKey.length, sessionData, 0);
        dataLen += aead.processBytes(authTag, 0, authTag.length, sessionData, dataLen);

        try
        {
            aead.doFinal(sessionData, dataLen);
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("Exception recovering session info", e);
        }

        return sessionData;
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
