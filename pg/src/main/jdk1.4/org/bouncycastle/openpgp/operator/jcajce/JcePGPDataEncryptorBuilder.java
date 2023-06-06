package org.bouncycastle.openpgp.operator.jcajce;

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.jcajce.io.CipherOutputStream;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPAEADDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;

/**
 * {@link PGPDataEncryptorBuilder} implementation that sources cryptographic primitives using the
 * JCE APIs.
 * <p>
 * By default, cryptographic primitives will be loaded using the default JCE load order (i.e.
 * without specifying a provider).
 * A specific provider can be specified using one of the {@link #setProvider(String)} methods.
 * </p>
 */
public class JcePGPDataEncryptorBuilder
    implements PGPDataEncryptorBuilder
{
    private final int encAlgorithm;

    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private JceAEADUtil aeadHelper = new JceAEADUtil(helper);
    private SecureRandom random;
    private boolean withIntegrityPacket = true;
    private int aeadAlgorithm = -1;
    private int chunkSize;
    private boolean isV5StyleAEAD = true; // TODO: change to false in 1.75

    /**
     * Constructs a new data encryptor builder for a specified cipher type.
     *
     * @param encAlgorithm one of the {@link SymmetricKeyAlgorithmTags supported symmetric cipher
     *                     algorithms}. May not be {@link SymmetricKeyAlgorithmTags#NULL}.
     */
    public JcePGPDataEncryptorBuilder(int encAlgorithm)
    {
        this.encAlgorithm = encAlgorithm;

        if (encAlgorithm == 0)
        {
            throw new IllegalArgumentException("null cipher specified");
        }
    }

    /**
     * Sets whether or not the resulting encrypted data will be protected using an integrity packet.
     *
     * @param withIntegrityPacket true if an integrity packet is to be included, false otherwise.
     * @return the current builder.
     */
    @Override
    public PGPDataEncryptorBuilder setWithIntegrityPacket(boolean withIntegrityPacket)
    {
        this.withIntegrityPacket = withIntegrityPacket;

        return this;
    }

    @Override
    public PGPDataEncryptorBuilder setWithAEAD(int aeadAlgorithm, int chunkSize)
    {
        if (encAlgorithm != SymmetricKeyAlgorithmTags.AES_128
            && encAlgorithm != SymmetricKeyAlgorithmTags.AES_192
            && encAlgorithm != SymmetricKeyAlgorithmTags.AES_256)
        {
            throw new IllegalStateException("AEAD algorithms can only be used with AES");
        }

        if (chunkSize < 6)
        {
            throw new IllegalArgumentException("minimum chunkSize is 6");
        }

        this.aeadAlgorithm = aeadAlgorithm;
        this.chunkSize = chunkSize - 6;

        return this;
    }

    @Override
    public PGPDataEncryptorBuilder setUseV5AEAD()
    {
        this.isV5StyleAEAD = true;

        return this;
    }

    @Override
    public PGPDataEncryptorBuilder setUseV6AEAD()
    {
        this.isV5StyleAEAD = false;

        return this;
    }

    /**
     * Sets the JCE provider to source cryptographic primitives from.
     *
     * @param provider the JCE provider to use.
     * @return the current builder.
     */
    public JcePGPDataEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));
        this.aeadHelper = new JceAEADUtil(helper);

        return this;
    }

    /**
     * Sets the JCE provider to source cryptographic primitives from.
     *
     * @param providerName the name of the JCE provider to use.
     * @return the current builder.
     */
    public JcePGPDataEncryptorBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        this.aeadHelper = new JceAEADUtil(helper);

        return this;
    }

    /**
     * Provide a user defined source of randomness.
     * <p>
     * If no SecureRandom is configured, a default SecureRandom will be used.
     * </p>
     *
     * @param random the secure random to be used.
     * @return the current builder.
     */
    public JcePGPDataEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    @Override
    public int getAlgorithm()
    {
        return encAlgorithm;
    }

    @Override
    public int getAeadAlgorithm()
    {
        return aeadAlgorithm;
    }

    @Override
    public int getChunkSize()
    {
        return chunkSize;
    }

    @Override
    public boolean isV5StyleAEAD()
    {
        return isV5StyleAEAD;
    }

    @Override
    public SecureRandom getSecureRandom()
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        return random;
    }

    @Override
    public PGPDataEncryptor build(byte[] keyBytes)
        throws PGPException
    {
        if (aeadAlgorithm > 0)
        {
            return new MyAeadDataEncryptor(keyBytes);
        }
        return new MyPGPDataEncryptor(keyBytes);
    }

    private class MyPGPDataEncryptor
        implements PGPDataEncryptor
    {
        private final Cipher c;

        MyPGPDataEncryptor(byte[] keyBytes)
            throws PGPException
        {
            c = helper.createStreamCipher(encAlgorithm, withIntegrityPacket);

            try
            {
                if (withIntegrityPacket)
                {
                    byte[] iv = new byte[c.getBlockSize()];

                    c.init(Cipher.ENCRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, keyBytes), new IvParameterSpec(iv));
                }
                else
                {
                    c.init(Cipher.ENCRYPT_MODE, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, keyBytes));
                }
            }
            catch (InvalidKeyException e)
            {
                throw new PGPException("invalid key: " + e.getMessage(), e);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new PGPException("imvalid algorithm parameter: " + e.getMessage(), e);
            }
        }

        public OutputStream getOutputStream(OutputStream out)
        {
            return new CipherOutputStream(out, c);
        }

        public PGPDigestCalculator getIntegrityCalculator()
        {
            if (withIntegrityPacket)
            {
                return new SHA1PGPDigestCalculator();
            }

            return null;
        }

        public int getBlockSize()
        {
            return c.getBlockSize();
        }
    }

    private class MyAeadDataEncryptor
        implements PGPAEADDataEncryptor
    {
        private final boolean isV5StyleAEAD;
        private final Cipher c;
        private final byte[] keyBytes;
        private final byte[] iv;

        /**
         * Create a new data decryptor using AEAD.
         * If OpenPGP v5 style AEAD is used, keyBytes contains the key. The IV is randomly generated.
         * If however OpenPGP v6 style AEAD is used, keyBytes contains M+N-8 bytes.
         * The first M bytes contain the key, the remaining N-8 bytes contain the IV.
         *
         * @param keyBytes key or key and iv
         * @throws PGPException on encryption failure
         */
        MyAeadDataEncryptor(byte[] keyBytes)
            throws PGPException
        {
            this.isV5StyleAEAD = keyBytes.length == SymmetricKeyUtils.getKeyLengthInOctets(encAlgorithm);
            if (isV5StyleAEAD)
            {
                this.keyBytes = keyBytes;
                // V5 has a random IV
                this.iv = new byte[AEADUtils.getIVLength((byte)aeadAlgorithm)];
                getSecureRandom().nextBytes(iv);
            }
            else
            {
                // V6 has the IV appended to the message key, so we need to split it
                byte[][] keyAndIv = AEADUtils.splitMessageKeyAndIv(keyBytes, encAlgorithm, aeadAlgorithm);
                this.keyBytes = keyAndIv[0];
                this.iv = keyAndIv[1];
            }
            this.c = aeadHelper.createAEADCipher(encAlgorithm, aeadAlgorithm);
        }

        public OutputStream getOutputStream(OutputStream out)
        {
            try
            {
                return new JceAEADUtil.PGPAeadOutputStream(isV5StyleAEAD, out, c, JcaJcePGPUtil.makeSymmetricKey(encAlgorithm, keyBytes), iv, encAlgorithm, aeadAlgorithm, chunkSize);
            }
            catch (Exception e)
            {
                throw new IllegalStateException("unable to process stream: " + e.getMessage());
            }
        }

        public PGPDigestCalculator getIntegrityCalculator()
        {
            return null;
        }

        public int getBlockSize()
        {
            return c.getBlockSize();
        }

        @Override
        public int getAEADAlgorithm()
        {
            return aeadAlgorithm;
        }

        @Override
        public int getChunkSize()
        {
            return chunkSize;
        }

        @Override
        public byte[] getIV()
        {
            return Arrays.clone(iv);
        }

    }
}
