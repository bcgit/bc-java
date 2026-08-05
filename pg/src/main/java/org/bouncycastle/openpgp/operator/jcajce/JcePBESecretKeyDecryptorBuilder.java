package org.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

public class JcePBESecretKeyDecryptorBuilder
        implements PBESecretKeyDecryptorBuilder
{
    private OperatorHelper helper = OperatorUtils.createDefaultHelper();
    private PGPDigestCalculatorProvider calculatorProvider;
    private JceAEADUtil aeadUtil = new JceAEADUtil(helper);

    private JcaPGPDigestCalculatorProviderBuilder calculatorProviderBuilder;

    public JcePBESecretKeyDecryptorBuilder()
    {
        this.calculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    }

    public JcePBESecretKeyDecryptorBuilder(PGPDigestCalculatorProvider calculatorProvider)
    {
        this.calculatorProvider = calculatorProvider;
    }

    public JcePBESecretKeyDecryptorBuilder setProvider(Provider provider)
    {
        this.helper = OperatorUtils.createProviderHelper(provider);
        this.aeadUtil = new JceAEADUtil(helper);

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(provider);
        }

        return this;
    }

    public JcePBESecretKeyDecryptorBuilder setProvider(String providerName)
    {
        this.helper = OperatorUtils.createNamedHelper(providerName);
        this.aeadUtil = new JceAEADUtil(helper);

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(providerName);
        }

        return this;
    }

    public PBESecretKeyDecryptor build(char[] passPhrase)
        throws PGPException
    {
        if (calculatorProvider == null)
        {
            calculatorProvider = calculatorProviderBuilder.build();
        }

        return new PBESecretKeyDecryptor(passPhrase, calculatorProvider, new JcePGPS2KCalculator(helper))
        {
            public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
                throws PGPException
            {
                return JcePBEKeyDataDecryptor.decryptKeyData(helper, encAlgorithm, "CFB", key,
                    new IvParameterSpec(iv), keyData, keyOff, keyLen);
            }

            @Override
            public byte[] recoverKeyData(int encAlgorithm, int aeadAlgorithm, byte[] s2kKey, byte[] iv, int packetTag, int keyVersion, byte[] keyData, byte[] pubkeyData)
                throws PGPException
            {
                return JceAEADUtil.processAeadKeyData(aeadUtil, Cipher.DECRYPT_MODE, encAlgorithm, aeadAlgorithm, s2kKey, iv, packetTag, keyVersion, keyData, 0, keyData.length, pubkeyData);
            }
        };
    }
}
