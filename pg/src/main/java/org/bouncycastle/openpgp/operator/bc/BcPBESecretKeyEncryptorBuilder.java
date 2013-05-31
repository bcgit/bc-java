package org.bouncycastle.openpgp.operator.bc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

public class BcPBESecretKeyEncryptorBuilder
{
    private int encAlgorithm;
    private PGPDigestCalculator s2kDigestCalculator;
    private SecureRandom random;
    private int s2kCount = 0x60;

    public BcPBESecretKeyEncryptorBuilder(int encAlgorithm)
    {
        this(encAlgorithm, new SHA1PGPDigestCalculator());
    }

    /**
     * Create an SecretKeyEncryptorBuilder with the S2K count different to the default of 0x60.
     *
     * @param encAlgorithm encryption algorithm to use.
     * @param s2kCount iteration count to use for S2K function.
     */
    public BcPBESecretKeyEncryptorBuilder(int encAlgorithm, int s2kCount)
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
    public BcPBESecretKeyEncryptorBuilder(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator)
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
    public BcPBESecretKeyEncryptorBuilder(int encAlgorithm, PGPDigestCalculator s2kDigestCalculator, int s2kCount)
    {
        this.encAlgorithm = encAlgorithm;
        this.s2kDigestCalculator = s2kDigestCalculator;

        if (s2kCount < 0 || s2kCount > 0xff)
        {
            throw new IllegalArgumentException("s2KCount value outside of range 0 to 255.");
        }

        this.s2kCount = s2kCount;
    }

    /**
     * Provide a user defined source of randomness.
     *
     * @param random  the secure random to be used.
     * @return  the current builder.
     */
    public BcPBESecretKeyEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public PBESecretKeyEncryptor build(char[] passPhrase)
    {
        if (this.random == null)
        {
            this.random = new SecureRandom();
        }

        return new PBESecretKeyEncryptor(encAlgorithm, s2kDigestCalculator, s2kCount, this.random, passPhrase)
        {
            private byte[] iv;

            public byte[] encryptKeyData(byte[] key, byte[] keyData, int keyOff, int keyLen)
                throws PGPException
            {
                return encryptKeyData(key, null, keyData, keyOff, keyLen);
            }

            public byte[] encryptKeyData(byte[] key, byte[] iv, byte[] keyData, int keyOff, int keyLen)
                throws PGPException
            {
                try
                {
                    BlockCipher engine = BcImplProvider.createBlockCipher(this.encAlgorithm);

                    if (iv != null)
                    {    // to deal with V3 key encryption
                        this.iv = iv;
                    }
                    else
                    {
                        if (this.random == null)
                        {
                            this.random = new SecureRandom();
                        }

                        this.iv = iv = new byte[engine.getBlockSize()];

                        this.random.nextBytes(iv);
                    }

                    BufferedBlockCipher c = BcUtil.createSymmetricKeyWrapper(true, engine, key, iv);

                    byte[] out = new byte[keyLen];
                    int    outLen = c.processBytes(keyData, keyOff, keyLen, out, 0);

                    outLen += c.doFinal(out, outLen);

                    return out;
                }
                catch (InvalidCipherTextException e)
                {
                    throw new PGPException("decryption failed: " + e.getMessage(), e);
                }
            }

            public byte[] getCipherIV()
            {
                return iv;
            }
        };
    }
}
