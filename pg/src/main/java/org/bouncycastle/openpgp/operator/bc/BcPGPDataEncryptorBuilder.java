package org.bouncycastle.openpgp.operator.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPAEADDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.util.Arrays;

/**
 * {@link PGPDataEncryptorBuilder} implementation that uses the Bouncy Castle lightweight API to
 * implement cryptographic primitives.
 */
public class BcPGPDataEncryptorBuilder
    implements PGPDataEncryptorBuilder
{
    private SecureRandom random;
    private boolean withIntegrityPacket = true;
    private int encAlgorithm;
    private boolean isV5StyleAEAD = true; // TODO: change to false in 1.75
    private int aeadAlgorithm = -1;
    private int chunkSize;

    /**
     * Constructs a new data encryptor builder for a specified cipher type.
     *
     * @param encAlgorithm one of the {@link SymmetricKeyAlgorithmTags supported symmetric cipher
     *                     algorithms}. May not be {@link SymmetricKeyAlgorithmTags#NULL}.
     */
    public BcPGPDataEncryptorBuilder(int encAlgorithm)
    {
        this.encAlgorithm = encAlgorithm;

        if (encAlgorithm == 0)
        {
            throw new IllegalArgumentException("null cipher specified");
        }
    }

    /**
     * Sets whether the resulting encrypted data will be protected using an integrity packet.
     *
     * @param withIntegrityPacket true if an integrity packet is to be included, false otherwise.
     * @return the current builder.
     */
    @Override
    public BcPGPDataEncryptorBuilder setWithIntegrityPacket(boolean withIntegrityPacket)
    {
        this.withIntegrityPacket = withIntegrityPacket;

        return this;
    }

    public BcPGPDataEncryptorBuilder setUseV5AEAD()
    {
        this.isV5StyleAEAD = true;

        return this;
    }

    public BcPGPDataEncryptorBuilder setUseV6AEAD()
    {
        this.isV5StyleAEAD = false;

        return this;
    }

    /**
     * Sets whether the resulting encrypted data will be protected using an AEAD mode.
     *
     * The chunkSize is used as a power of two, result in blocks (1 &lt;&lt; chunkSize) containing data
     * with an extra 16 bytes for the tag. The minimum chunkSize is 6.
     *
     * @param aeadAlgorithm the AEAD mode to use.
     * @param chunkSize     the size of the chunks to be processed with each nonce.
     * @return builder
     */
    @Override
    public BcPGPDataEncryptorBuilder setWithAEAD(int aeadAlgorithm, int chunkSize)
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

    /**
     * Provide a user defined source of randomness.
     * <p>
     * If no SecureRandom is configured, a default SecureRandom will be used.
     * </p>
     *
     * @param random the secure random to be used.
     * @return the current builder.
     */
    public BcPGPDataEncryptorBuilder setSecureRandom(SecureRandom random)
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
        private final BufferedBlockCipher c;

        MyPGPDataEncryptor(byte[] keyBytes)
            throws PGPException
        {
            BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

            try
            {
                c = BcUtil.createStreamCipher(true, engine, withIntegrityPacket, keyBytes);
            }
            catch (IllegalArgumentException e)
            {
                throw new PGPException("invalid parameters: " + e.getMessage(), e);
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
        private final AEADBlockCipher c;
        private final byte[] keyBytes;
        private final byte[] iv;

        /**
         * Create a new data decryptor using AEAD.
         * If the OpenPGP v5 style AEAD is used, keyBytes contains the key. The IV is randomly generated.
         * If however OpenPGP v6 style AEAD is used, keyBytes contains M+N-8 bytes.
         * The first M bytes contain the key, the remaining N-8 bytes contain the IV.
         *
         * @param keyBytes key or key and iv
         * @throws PGPException
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
            // V6 passes in concatenated key and N-8 bytes of IV.
            else
            {
                // V6 has the IV appended to the message key, so we need to split it.
                byte[][] keyAndIv = AEADUtils.splitMessageKeyAndIv(keyBytes, encAlgorithm, aeadAlgorithm);
                this.keyBytes = keyAndIv[0];
                this.iv = keyAndIv[1];
            }

            this.c = BcAEADUtil.createAEADCipher(encAlgorithm, aeadAlgorithm);
        }

        public OutputStream getOutputStream(OutputStream out)
        {
            try
            {
                return new BcAEADUtil.PGPAeadOutputStream(isV5StyleAEAD, out, c, new KeyParameter(keyBytes), iv, encAlgorithm, aeadAlgorithm, chunkSize);
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
            return c.getUnderlyingCipher().getBlockSize();
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
