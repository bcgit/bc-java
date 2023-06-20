package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;

public class JcePBESecretKeyDecryptorBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JceAEADUtil aeadHelper = new JceAEADUtil(helper);
    private PGPDigestCalculatorProvider calculatorProvider;

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
        this.aeadHelper = new JceAEADUtil(helper);

        if (calculatorProviderBuilder != null)
        {
            calculatorProviderBuilder.setProvider(provider);
        }

        return this;
    }

    public JcePBESecretKeyDecryptorBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        this.aeadHelper = new JceAEADUtil(helper);

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
            public byte[] recoverAEADEncryptedKeyData(SecretKeyPacket secret, byte[] key)
                    throws IOException, PGPException
            {
                int encAlgorithm = secret.getEncAlgorithm();
                int aeadAlgorithm = secret.getAeadAlgorithm();
                byte[] hkdfInfo = new byte[] {
                        (byte) (secret instanceof SecretSubkeyPacket ?
                                0xC0 | PacketTags.SECRET_SUBKEY :
                                0xC0 | PacketTags.SECRET_KEY), // TODO: 0xC0 | secret.getPacketTag()
                        (byte) secret.getVersion(),
                        (byte) encAlgorithm,
                        (byte) aeadAlgorithm
                };

                int kekLength = SymmetricKeyUtils.getKeyLengthInOctets(encAlgorithm);
                byte[] salt = null;
                byte[] kek = aeadHelper.hkdfDeriveKey(hkdfInfo, salt, kekLength, key);

                byte[] aad = Arrays.prepend(secret.getPublicKeyPacket().getEncodedContents(),
                        (byte) (secret instanceof SecretSubkeyPacket ?
                        0xC0 | PacketTags.SECRET_SUBKEY :
                        0xC0 | PacketTags.SECRET_KEY));
                byte[] aeadIv = secret.getIV();
                int aeadMacLen = 128;

                byte[] ciphertextAndAuthTag = secret.getSecretKeyData();
                byte[] sessionData;
                try
                {
                    sessionData = aeadHelper.decryptAEAD(encAlgorithm, aeadAlgorithm, kek, aeadMacLen, aeadIv, ciphertextAndAuthTag, aad);
                    return sessionData;
                }
                catch (GeneralSecurityException e)
                {
                    throw new PGPException("unable to open stream: " + e.getMessage());
                }
            }
        };
    }
}
