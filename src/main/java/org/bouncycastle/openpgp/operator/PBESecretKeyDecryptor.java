package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;

public abstract class PBESecretKeyDecryptor
{
    private char[] passPhrase;
    private PGPDigestCalculatorProvider calculatorProvider;

    protected PBESecretKeyDecryptor(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        this.passPhrase = passPhrase;
        this.calculatorProvider = calculatorProvider;
    }

    public PGPDigestCalculator getChecksumCalculator(int hashAlgorithm)
        throws PGPException
    {
        return calculatorProvider.get(hashAlgorithm);
    }

    public byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k)
        throws PGPException
    {
        return PGPUtil.makeKeyFromPassPhrase(calculatorProvider, keyAlgorithm, s2k, passPhrase);
    }

    public abstract byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
        throws PGPException;
}
