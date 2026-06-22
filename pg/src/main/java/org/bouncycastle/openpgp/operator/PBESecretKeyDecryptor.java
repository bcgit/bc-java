package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;

public abstract class PBESecretKeyDecryptor
{
    private char[] passPhrase;
    private PGPDigestCalculatorProvider calculatorProvider;
    private PGPS2KCalculator s2kCalculator;

    protected PBESecretKeyDecryptor(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        this(passPhrase, calculatorProvider, null);
    }

    protected PBESecretKeyDecryptor(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider, PGPS2KCalculator s2kCalculator)
    {
        this.passPhrase = passPhrase;
        this.calculatorProvider = calculatorProvider;
        this.s2kCalculator = s2kCalculator;
    }

    public PGPDigestCalculator getChecksumCalculator(int hashAlgorithm)
        throws PGPException
    {
        return calculatorProvider.get(hashAlgorithm);
    }

    public byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k)
        throws PGPException
    {
        return PGPUtil.makeKeyFromPassPhrase(calculatorProvider, s2kCalculator, keyAlgorithm, s2k, passPhrase);
    }

    public abstract byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
        throws PGPException;

    public abstract byte[] recoverKeyData(
        int encAlgorithm,
        int aeadAlgorithm,
        byte[] s2kKey,
        byte[] iv,
        int packetTag,
        int keyVersion,
        byte[] keyData,
        byte[] pubkeyData)
        throws PGPException;
}
