package org.bouncycastle.openpgp.operator.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

/**
 * {@link PGPDataEncryptorBuilder} implementation that uses the Bouncy Castle lightweight API to
 * implement cryptographic primitives.
 */
public class BcPGPDataEncryptorBuilder
    implements PGPDataEncryptorBuilder
{
    private SecureRandom   random;
    private boolean withIntegrityPacket;
    private int encAlgorithm;

    /**
     * Constructs a new data encryptor builder for a specified cipher type.
     * 
     * @param encAlgorithm one of the {@link SymmetricKeyAlgorithmTags supported symmetric cipher
     *            algorithms}. May not be {@link SymmetricKeyAlgorithmTags#NULL}.
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
     * Sets whether or not the resulting encrypted data will be protected using an integrity packet.
     *
     * @param withIntegrityPacket true if an integrity packet is to be included, false otherwise.
     * @return the current builder.
     */
    public BcPGPDataEncryptorBuilder setWithIntegrityPacket(boolean withIntegrityPacket)
    {
        this.withIntegrityPacket = withIntegrityPacket;

        return this;
    }

    /**
     * Provide a user defined source of randomness.
     * <p>
     * If no SecureRandom is configured, a default SecureRandom will be used.
     * </p>
     * @param random the secure random to be used.
     * @return the current builder.
     */
    public BcPGPDataEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public int getAlgorithm()
    {
        return encAlgorithm;
    }

    public SecureRandom getSecureRandom()
    {
        if (random == null)
        {
            random = new SecureRandom();
        }

        return random;
    }

    public PGPDataEncryptor build(byte[] keyBytes)
        throws PGPException
    {
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
}
