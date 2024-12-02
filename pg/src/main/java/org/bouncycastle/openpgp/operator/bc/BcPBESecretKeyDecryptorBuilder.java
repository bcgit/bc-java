package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

public class BcPBESecretKeyDecryptorBuilder
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
                return BcAEADUtil.processAeadKeyData(false, encAlgorithm, aeadAlgorithm, s2kKey, iv, packetTag, keyVersion, keyData, 0, keyData.length, pubkeyData);
            }
        };
    }
}
