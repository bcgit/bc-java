package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

public class JcePBESecretKeyEncryptorBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private int encAlgorithm;
    private PGPDigestCalculator s2kDigestCalculator;
    private SecureRandom random;
    private int s2kCount = 0x60;

    public JcePBESecretKeyEncryptorBuilder(int encAlgorithm)
    {
        this(encAlgorithm, new SHA1PGPDigestCalculator());
    }

    /**
     * Create a SecretKeyEncryptorBuilder with the S2K count different to the default of 0x60.
     *
     * @param encAlgorithm encryption algorithm to use.
     * @param s2kCount iteration count to use for S2K function.
     */
    public JcePBESecretKeyEncryptorBuilder(int encAlgorithm, int s2kCount)
    {
        this(encAlgorithm, new SHA1PGPDigestCalculator(), s2kCount);
    }

    /**
     * Create a builder which will make encryptors using the passed in digest calculator. If a MD5 calculator is
     * passed in the builder will assume the encryptors are for use with version 3 keys.
     *
     * @param encAlgorithm  encryption algorithm to use.
     * @param s2kDigestCalculator digest calculator to use.
     */
    public JcePBESecretKeyEncryptorBuilder(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator)
    {
        this(encAlgorithm, s2kDigestCalculator, 0x60);
    }

    /**
     * Create an SecretKeyEncryptorBuilder with the S2k count different to the default of 0x60, and the S2K digest
     * different from SHA-1.
     *
     * @param encAlgorithm encryption algorithm to use.
     * @param s2kDigestCalculator digest calculator to use.
     * @param s2kCount iteration count to use for S2K function.
     */
    public JcePBESecretKeyEncryptorBuilder(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, int s2kCount)
    {
        this.encAlgorithm = encAlgorithm;
        this.s2kDigestCalculator = s2kDigestCalculator;

        if (s2kCount < 0 || s2kCount > 0xff)
        {
            throw new IllegalArgumentException("s2KCount value outside of range 0 to 255.");
        }

        this.s2kCount = s2kCount;
    }

    public JcePBESecretKeyEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcePBESecretKeyEncryptorBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

   /**
     * Provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current builder.
     */
    public JcePBESecretKeyEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public PBESecretKeyEncryptor build(char[] passPhrase)
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        return new PBESecretKeyEncryptor(encAlgorithm, s2kDigestCalculator, s2kCount, random, passPhrase)
        {
            private Cipher c;
            private byte[] iv;

            public byte[] encryptKeyData(byte[] key, byte[] keyData, int keyOff, int keyLen)
                throws PGPException
            {
                try
                {
                    c = helper.createCipher(PGPUtil.getSymmetricCipherName(this.encAlgorithm) + "/CFB/NoPadding");

                    c.init(Cipher.ENCRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(this.encAlgorithm, key), this.random);

                    iv = c.getIV();

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
                catch (InvalidKeyException e)
                {
                    throw new PGPException("invalid key: " + e.getMessage(), e);
                }
            }

            public byte[] encryptKeyData(byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
                throws PGPException
            {
                try
                {
                    c = helper.createCipher(PGPUtil.getSymmetricCipherName(this.encAlgorithm) + "/CFB/NoPadding");

                    c.init(Cipher.ENCRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(this.encAlgorithm, key), new IvParameterSpec(iv));

                    this.iv = iv;

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
                catch (InvalidKeyException e)
                {
                    throw new PGPException("invalid key: " + e.getMessage(), e);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new PGPException("invalid iv: " + e.getMessage(), e);
                }
            }

            public byte[] getCipherIV()
            {
                return iv;
            }
        };
    }
}
