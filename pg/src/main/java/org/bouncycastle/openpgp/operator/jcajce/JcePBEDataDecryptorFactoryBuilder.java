package org.bouncycastle.openpgp.operator.jcajce;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Provider;

/**
 * Builder for {@link PBEDataDecryptorFactory} instances that obtain cryptographic primitives using
 * the JCE API.
 */
public class JcePBEDataDecryptorFactoryBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JceAEADUtil aeadHelper = new JceAEADUtil(helper);
    private PGPDigestCalculatorProvider calculatorProvider;

    /**
     * Base constructor - assume the required digest calculators can be provided from the same source as
     * the cipher needed.
     */
    public JcePBEDataDecryptorFactoryBuilder()
    {
        this.calculatorProvider = null;
    }

    /**
     * Base constructor.
     *
     * @param calculatorProvider   a digest calculator provider to provide calculators to support the key generation calculation required.
     */
    public JcePBEDataDecryptorFactoryBuilder(PGPDigestCalculatorProvider calculatorProvider)
    {
        this.calculatorProvider = calculatorProvider;
    }

    /**
     * Set the provider object to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param provider  provider object for cryptographic primitives.
     * @return  the current builder.
     */
    public JcePBEDataDecryptorFactoryBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        this.aeadHelper = new JceAEADUtil(helper);

        return this;
    }

    /**
     * Set the provider name to use for creating cryptographic primitives in the resulting factory the builder produces.
     *
     * @param providerName  the name of the provider to reference for cryptographic primitives.
     * @return  the current builder.
     */
    public JcePBEDataDecryptorFactoryBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        this.aeadHelper = new JceAEADUtil(helper);

        return this;
    }

    /**
     * Construct a {@link PBEDataDecryptorFactory} to use to decrypt PBE encrypted data.
     *
     * @param passPhrase the pass phrase to use to generate keys in the resulting factory.
     * @return a decryptor factory that can be used to generate PBE keys.
     */
    public PBEDataDecryptorFactory build(char[] passPhrase)
    {
        if (calculatorProvider == null)
        {
            try
            {
                calculatorProvider = new JcaPGPDigestCalculatorProviderBuilder(helper).build();
            }
            catch (PGPException e)
            {
                throw new IllegalStateException("digest calculator provider cannot be built with current helper: " + e.getMessage());
            }
        }
        return new PBEDataDecryptorFactory(passPhrase, calculatorProvider)
        {
            @Override
            public byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] secKeyData)
                    throws PGPException
            {
                try
                {
                    if (secKeyData != null && secKeyData.length > 0)
                    {
                        String cipherName = PGPUtil.getSymmetricCipherName(keyAlgorithm);
                        Cipher keyCipher = helper.createCipher(cipherName + "/CFB/NoPadding");

                        keyCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, cipherName), new IvParameterSpec(new byte[keyCipher.getBlockSize()]));

                        return keyCipher.doFinal(secKeyData);
                    }
                    else
                    {
                        byte[] keyBytes = new byte[key.length + 1];

                        keyBytes[0] = (byte)keyAlgorithm;
                        System.arraycopy(key, 0, keyBytes, 1, key.length);

                        return keyBytes;
                    }
                }
                catch (Exception e)
                {
                    throw new PGPException("Exception recovering session info", e);
                }
            }

            @Override
            public byte[] recoverAEADEncryptedSessionData(SymmetricKeyEncSessionPacket keyData, byte[] ikm)
                    throws PGPException
            {
                if (keyData.getVersion() < SymmetricKeyEncSessionPacket.VERSION_5)
                {
                    throw new PGPException("SKESK packet MUST be version 5 or later.");
                }

                byte[] hkdfInfo = keyData.getAAData(); // between v5 and v6, these bytes differ
                int kekLen = SymmetricKeyUtils.getKeyLengthInOctets(keyData.getEncAlgorithm());
                byte[] salt = null;
                byte[] kek = JceAEADUtil.hkdfDeriveKey(hkdfInfo, salt, kekLen, ikm);

                int encAlgorithm = keyData.getEncAlgorithm();
                int aeadAlgorithm = keyData.getAeadAlgorithm();

                byte[] aad = hkdfInfo;
                byte[] aeadIv = keyData.getIv();
                int aeadMacLen = 128;

                // AEAD
                byte[] authTag = keyData.getAuthTag();
                byte[] encSessionKey = keyData.getSecKeyData();
                byte[] ciphertextAndAuthTag = Arrays.concatenate(encSessionKey, authTag);

                byte[] sessionData;
                try
                {
                    sessionData = aeadHelper.decryptAEAD(encAlgorithm, aeadAlgorithm, kek, aeadMacLen, aeadIv, ciphertextAndAuthTag, aad);
                }
                catch (GeneralSecurityException e)
                {
                    throw new PGPException("unable to open stream: " + e.getMessage());
                }

                return sessionData;

            }

            // OpenPGP v4
            @Override
            public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                    throws PGPException
            {
                return helper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
            }

            // OpenPGP v5
            @Override
            public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket, PGPSessionKey sessionKey)
                    throws PGPException
            {
                return aeadHelper.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
            }

            // OpenPGP v6
            @Override
            public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd, PGPSessionKey sessionKey)
                    throws PGPException
            {
                return aeadHelper.createOpenPgpV6DataDecryptor(seipd, sessionKey);
            }
        };
    }
}
