package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

public class JcePBESecretKeyDecryptorBuilder
        implements PBESecretKeyDecryptorBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
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
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        this.aeadUtil = new JceAEADUtil(helper);

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(provider);
        }

        return this;
    }

    public JcePBESecretKeyDecryptorBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
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

        return new PBESecretKeyDecryptor(passPhrase, calculatorProvider)
        {
            public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
                throws PGPException
            {
                try
                {
                    Cipher c = helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/CFB/NoPadding");

                    c.init(Cipher.DECRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, key), new IvParameterSpec(iv));

                    return c.doFinal(keyData, keyOff, keyLen);
                }
                catch (IllegalBlockSizeException e)
                {
                    throw new PGPException("illegal block size: " + e.getMessage(), e);
                }
                catch (BadPaddingException e)
                {
                    throw new PGPException("bad padding: " + e.getMessage(), e);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new PGPException("invalid parameter: " + e.getMessage(), e);
                }
                catch (InvalidKeyException e)
                {
                    throw new PGPException("invalid key: " + e.getMessage(), e);
                }
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
