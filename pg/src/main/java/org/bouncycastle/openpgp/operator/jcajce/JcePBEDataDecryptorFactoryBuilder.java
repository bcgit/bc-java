package org.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

/**
 * Builder for {@link PBEDataDecryptorFactory} instances that obtain cryptographic primitives using
 * the JCE API.
 */
public class JcePBEDataDecryptorFactoryBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
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
         return new JcePBEDataDecryptorFactory(helper, passPhrase, calculatorProvider);
    }

    private static class JcePBEDataDecryptorFactory extends PBEDataDecryptorFactory
    {

        private final OperatorHelper helper;

        protected JcePBEDataDecryptorFactory(OperatorHelper helper)
        {
            super();
            this.helper = helper;
        }

        protected JcePBEDataDecryptorFactory(OperatorHelper helper, char[] passphrase, PGPDigestCalculatorProvider digestCalculatorProvider)
        {
            super(passphrase, digestCalculatorProvider);
            this.helper = helper;
        }

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

        public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                throws PGPException
        {
            return helper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
        }
    }

    /**
     * Create an instance of the {@link JcePBEDataDecryptorFactory} which is based on the provided session key.
     * This factory will not source the session key from decrypting a symmetric key encrypted session key packet (SKESK)
     * with a passphrase, but instead use the provided session key directly to decrypt the data.
     *
     * @param sessionKeyAlgorithm session key algorithm
     * @param sessionKey session key
     * @return decryptor factory
     */
    public PBEDataDecryptorFactory createFactoryFromSessionKey(int sessionKeyAlgorithm, byte[] sessionKey)
    {
        return new JcePBEDataDecryptorFactory(helper)
        {
            @Override
            public byte[] makeKeyFromPassPhrase(int keyAlgorithm, S2K s2k)
                    throws PGPException
            {
                if (keyAlgorithm != sessionKeyAlgorithm)
                {
                    throw new PGPException("Unexpected symmetric key algorithm encountered. Expected " + sessionKeyAlgorithm + ", got " + keyAlgorithm);
                }
                return sessionKey;
            }
        };
    }
}
