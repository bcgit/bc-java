package org.bouncycastle.openpgp.operator.jcajce;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEProtectionRemoverFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PGPSecretKeyDecryptorWithAAD;
import org.bouncycastle.util.Arrays;

public class JcePBEProtectionRemoverFactory
    implements PBEProtectionRemoverFactory
{
    private final char[] passPhrase;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
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
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        this.aeadUtil = new JceAEADUtil(helper);

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(provider);
        }

        return this;
    }

    public JcePBEProtectionRemoverFactory setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
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
            return new PGPSecretKeyDecryptorWithAAD(passPhrase, calculatorProvider)
            {
                public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] aad, byte[] keyData,  int keyOff, int keyLen)
                    throws PGPException
                {
                    try
                    {
                        Cipher c;
                        c = helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/OCB/NoPadding");
                        c.init(Cipher.DECRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, key), new AEADParameterSpec(iv, 128, aad));
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
                    byte[] hkdfInfo = new byte[] {
                        (byte) (0xC0 | packetTag), (byte) keyVersion, (byte) encAlgorithm, (byte) aeadAlgorithm
                    };
                    // TODO: Replace HDKF code with JCE based implementation
                    HKDFParameters hkdfParameters = new HKDFParameters(s2kKey, null, hkdfInfo);
                    HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());
                    hkdfGen.init(hkdfParameters);
                    byte[] key = new byte[SymmetricKeyUtils.getKeyLengthInOctets(encAlgorithm)];
                    hkdfGen.generateBytes(key, 0, key.length);

                    byte[] aad = Arrays.prepend(pubkeyData, (byte) (0xC0 | packetTag));

                    SecretKey secretKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));
                    final Cipher c = aeadUtil.createAEADCipher(encAlgorithm, aeadAlgorithm);
                    try
                    {
                        JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.DECRYPT_MODE, iv, 128, aad);
                        byte[] data = c.doFinal(keyData);
                        return data;
                    }
                    catch (Exception e)
                    {
                        throw new PGPException("Cannot extract AEAD protected secret key material", e);
                    }
                }
            };
        }
        else
        {
            return new PBESecretKeyDecryptor(passPhrase, calculatorProvider)
            {
                public byte[] recoverKeyData(int encAlgorithm, byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
                    throws PGPException
                {
                    try
                    {
                        Cipher c;
                        c = helper.createCipher(PGPUtil.getSymmetricCipherName(encAlgorithm) + "/CBC/NoPadding");
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
                    byte[] hkdfInfo = new byte[] {
                        (byte) (0xC0 | packetTag), (byte) keyVersion, (byte) encAlgorithm, (byte) aeadAlgorithm
                    };
                    // TODO: Replace HDKF code with JCE based implementation
                    HKDFParameters hkdfParameters = new HKDFParameters(s2kKey, null, hkdfInfo);
                    HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());
                    hkdfGen.init(hkdfParameters);
                    byte[] key = new byte[SymmetricKeyUtils.getKeyLengthInOctets(encAlgorithm)];
                    hkdfGen.generateBytes(key, 0, key.length);

                    byte[] aad = Arrays.prepend(pubkeyData, (byte) (0xC0 | packetTag));

                    SecretKey secretKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));
                    final Cipher c = aeadUtil.createAEADCipher(encAlgorithm, aeadAlgorithm);
                    try
                    {
                        JceAEADCipherUtil.setUpAeadCipher(c, secretKey, Cipher.DECRYPT_MODE, iv, 128, aad);
                        byte[] data = c.doFinal(keyData);
                        return data;
                    }
                    catch (Exception e)
                    {
                        throw new PGPException("Cannot extract AEAD protected secret key material", e);
                    }
                }
            };

        }
    }
}
