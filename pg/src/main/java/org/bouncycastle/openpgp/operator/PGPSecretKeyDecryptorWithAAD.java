package org.bouncycastle.openpgp.operator;

import org.bouncycastle.openpgp.PGPException;

public abstract class PGPSecretKeyDecryptorWithAAD
    extends PBESecretKeyDecryptor
{
    public PGPSecretKeyDecryptorWithAAD(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        super(passPhrase, calculatorProvider);
    }

    public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
        throws PGPException
    {
        return recoverKeyData(encAlgorithm, key, iv, null, keyData, keyOff, keyLen);
    }

    public abstract byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] aad, byte[] keyData, int keyOff, int keyLen) throws PGPException;
}
