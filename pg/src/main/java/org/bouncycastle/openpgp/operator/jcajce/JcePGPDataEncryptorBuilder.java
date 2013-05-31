package org.bouncycastle.openpgp.operator.jcajce;

import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDataEncryptor;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

public class JcePGPDataEncryptorBuilder
    implements PGPDataEncryptorBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private SecureRandom   random;
    private boolean withIntegrityPacket;
    private int encAlgorithm;

    public JcePGPDataEncryptorBuilder(int encAlgorithm)
    {
        this.encAlgorithm = encAlgorithm;

        if (encAlgorithm == 0)
        {
            throw new IllegalArgumentException("null cipher specified");
        }
    }

    /**
     * Determine whether or not the resulting encrypted data will be protected using an integrity packet.
     *
     * @param withIntegrityPacket true if an integrity packet is to be included, false otherwise.
     * @return  the current builder.
     */
    public JcePGPDataEncryptorBuilder setWithIntegrityPacket(boolean withIntegrityPacket)
    {
        this.withIntegrityPacket = withIntegrityPacket;

        return this;
    }

    public JcePGPDataEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcePGPDataEncryptorBuilder setProvider(String providerName)
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
    public JcePGPDataEncryptorBuilder setSecureRandom(SecureRandom random)
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
        private final Cipher c;

        MyPGPDataEncryptor(byte[] keyBytes)
            throws PGPException
        {
            c = helper.createStreamCipher(encAlgorithm, withIntegrityPacket);

            byte[] iv = new byte[c.getBlockSize()];

            try
            {
                c.init(Cipher.ENCRYPT_MODE, PGPUtil.makeSymmetricKey(encAlgorithm, keyBytes), new IvParameterSpec(iv));
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
}
