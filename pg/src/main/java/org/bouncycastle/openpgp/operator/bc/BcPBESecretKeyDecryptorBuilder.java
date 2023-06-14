package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;

import java.io.IOException;

public class BcPBESecretKeyDecryptorBuilder
{
    private PGPDigestCalculatorProvider calculatorProvider;
    private BcAEADUtil aeadHelper = new BcAEADUtil();

    public BcPBESecretKeyDecryptorBuilder(PGPDigestCalculatorProvider calculatorProvider)
    {
        this.calculatorProvider = calculatorProvider;
    }

    public PBESecretKeyDecryptor build(char[] passPhrase)
    {
        return new PBESecretKeyDecryptor(passPhrase, calculatorProvider)
        {
            public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
                throws PGPException
            {
                try
                {
                    BufferedBlockCipher c = BcUtil.createSymmetricKeyWrapper(false, BcImplProvider.createBlockCipher(encAlgorithm), key, iv);

                    byte[] out = new byte[keyLen];
                    int    outLen = c.processBytes(keyData, keyOff, keyLen, out, 0);

                    outLen += c.doFinal(out, outLen);

                    return out;
                }
                catch (InvalidCipherTextException e)
                {
                    throw new PGPException("decryption failed: " + e.getMessage(), e);
                }
            }

            @Override
            public byte[] recoverAEADEncryptedKeyData(SecretKeyPacket secret, byte[] key) throws IOException, PGPException {
                // HKDF
                // [tag, version, symAlg, aeadAlg]
                byte[] hkdfInfo = new byte[] {
                        (byte) (secret instanceof SecretSubkeyPacket ?
                                0xC0 | PacketTags.SECRET_SUBKEY :
                                0xC0 | PacketTags.SECRET_KEY), // TODO: 0xC0 | secret.getPacketTag()
                        (byte) secret.getVersion(),
                        (byte) secret.getEncAlgorithm(),
                        (byte) secret.getAeadAlgorithm()
                };
                int kekLen = SymmetricKeyUtils.getKeyLengthInOctets(secret.getEncAlgorithm());
                byte[] salt = null;
                byte[] kek = aeadHelper.hkdfDeriveKey(hkdfInfo, salt, kekLen, key);

                // AEAD
                byte[] aad = Arrays.prepend(secret.getPublicKeyPacket().getEncodedContents(),
                        (byte) (secret instanceof SecretSubkeyPacket ?
                                0xC0 | PacketTags.SECRET_SUBKEY :
                                0xC0 | PacketTags.SECRET_KEY));

                int encAlgorithm = secret.getEncAlgorithm();
                int aeadAlgorithm = secret.getAeadAlgorithm();
                int aeadMacLen = 128;
                byte[] aeadIv = secret.getIV();

                byte[] ciphertextAndAuthTag = secret.getSecretKeyData();
                byte[] sessionData;
                try {
                    sessionData = aeadHelper.decryptAEAD(encAlgorithm, aeadAlgorithm, kek, aeadMacLen, aeadIv, ciphertextAndAuthTag, aad);
                }
                catch (PGPException | InvalidCipherTextException e)
                {
                    throw new PGPException("Exception recovering session info", e);
                }

                return sessionData;
            }
        };
    }
}
