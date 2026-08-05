package org.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPSecretKeyDecryptorWithAAD;

public class JcePBEProtectionRemoverFactory
    implements PBEProtectionRemoverFactory
{
    private final char[] passPhrase;

    private OperatorHelper helper = OperatorUtils.createDefaultHelper();
    private PGPDigestCalculatorProvider calculatorProvider;
    private JceAEADUtil aeadUtil = new JceAEADUtil(helper);

    private JcaPGPDigestCalculatorProviderBuilder calculatorProviderBuilder;

    public JcePBEProtectionRemoverFactory(char[] passPhrase)
    {
        this.passPhrase = passPhrase;
        this.calculatorProviderBuilder = new JcaPGPDigestCalculatorProviderBuilder();
    }

    public JcePBEProtectionRemoverFactory(char[] passPhrase, PGPDigestCalculatorProvider calculatorProvider)
    {
        this.passPhrase = passPhrase;
        this.calculatorProvider = calculatorProvider;
    }

    public JcePBEProtectionRemoverFactory setProvider(Provider provider)
    {
        this.helper = OperatorUtils.createProviderHelper(provider);
        this.aeadUtil = new JceAEADUtil(helper);

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(provider);
        }

        return this;
    }

    public JcePBEProtectionRemoverFactory setProvider(String providerName)
    {
        this.helper = OperatorUtils.createNamedHelper(providerName);
        this.aeadUtil = new JceAEADUtil(helper);

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(providerName);
        }

        return this;
    }

    public PBESecretKeyDecryptor createDecryptor(String protection)
        throws PGPException
    {
        if (calculatorProvider == null)
        {
            calculatorProvider = calculatorProviderBuilder.build();
        }

        if (protection.indexOf("ocb") >= 0)
        {
            return new PGPSecretKeyDecryptorWithAAD(passPhrase, calculatorProvider, new JcePGPS2KCalculator(helper))
            {
                public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] aad, byte[] keyData,  int keyOff, int keyLen)
                    throws PGPException
                {
                    return JcePBEKeyDataDecryptor.decryptKeyData(helper, encAlgorithm, "OCB", key,
                        new AEADParameterSpec(iv, 128, aad), keyData, keyOff, keyLen);
                }

                @Override
                public byte[] recoverKeyData(int encAlgorithm, int aeadAlgorithm, byte[] s2kKey, byte[] iv, int packetTag, int keyVersion, byte[] keyData, byte[] pubkeyData) 
                    throws PGPException
                {
                    return JceAEADUtil.processAeadKeyData(aeadUtil, Cipher.DECRYPT_MODE, encAlgorithm, aeadAlgorithm, s2kKey, iv, packetTag, keyVersion, keyData, 0, keyData.length, pubkeyData);
                }
            };
        }
        else
        {
            return new PBESecretKeyDecryptor(passPhrase, calculatorProvider, new JcePGPS2KCalculator(helper))
            {
                public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
                    throws PGPException
                {
                    return JcePBEKeyDataDecryptor.decryptKeyData(helper, encAlgorithm, "CBC", key,
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
}
