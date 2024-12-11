package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;

public class BcPBESecretKeyDecryptorBuilder
        implements PBESecretKeyDecryptorBuilder
{
    private PGPDigestCalculatorProvider calculatorProvider;

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
            public byte[] recoverKeyData(int encAlgorithm, int aeadAlgorithm, byte[] s2kKey, byte[] iv, int packetTag, int keyVersion, byte[] keyData, byte[] pubkeyData) throws PGPException
            {
                byte[] hkdfInfo = new byte[] {
                    (byte) (0xC0 | packetTag), (byte) keyVersion, (byte) encAlgorithm, (byte) aeadAlgorithm
                };

                HKDFParameters hkdfParameters = new HKDFParameters(s2kKey, null, hkdfInfo);
                HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());
                hkdfGen.init(hkdfParameters);
                byte[] key = new byte[SymmetricKeyUtils.getKeyLengthInOctets(encAlgorithm)];
                hkdfGen.generateBytes(key, 0, key.length);

                byte[] aad = Arrays.prepend(pubkeyData, (byte) (0xC0 | packetTag));
                AEADBlockCipher cipher = BcAEADUtil.createAEADCipher(encAlgorithm, aeadAlgorithm);
                cipher.init(false, new AEADParameters(
                    new KeyParameter(key),
                    128,
                    iv,
                    aad
                ));
                int dataLen = cipher.getOutputSize(keyData.length);
                byte[] data = new byte[dataLen];
                dataLen = cipher.processBytes(keyData, 0, keyData.length, data, 0);

                try
                {
                    cipher.doFinal(data, dataLen);
                    return data;
                }
                catch (InvalidCipherTextException e)
                {
                    throw new PGPException("Exception recovering AEAD protected private key material", e);
                }
            }
        };
    }
}
