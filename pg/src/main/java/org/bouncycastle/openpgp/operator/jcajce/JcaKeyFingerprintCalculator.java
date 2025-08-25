package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

public class JcaKeyFingerprintCalculator
    implements KeyFingerPrintCalculator
{
    private final JcaJceHelper helper;

    /**
     * Base Constructor - use the JCA defaults.
     */
    public JcaKeyFingerprintCalculator()
    {
        this(new DefaultJcaJceHelper());
    }

    private JcaKeyFingerprintCalculator(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param provider the JCA provider to use.
     * @return a new JceKeyFingerprintCalculator supported by the passed in provider.
     */
    public JcaKeyFingerprintCalculator setProvider(Provider provider)
    {
        return new JcaKeyFingerprintCalculator(new ProviderJcaJceHelper(provider));
    }

    /**
     * Sets the provider to use to obtain cryptographic primitives.
     *
     * @param providerName the name of the JCA provider to use.
     * @return a new JceKeyFingerprintCalculator supported by the passed in named provider.
     */
    public JcaKeyFingerprintCalculator setProvider(String providerName)
    {
        return new JcaKeyFingerprintCalculator(new NamedJcaJceHelper(providerName));
    }

    public byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException
    {
        BCPGKey key = publicPk.getKey();

        if (publicPk.getVersion() <= PublicKeyPacket.VERSION_3)
        {
            if (!(key instanceof RSAPublicBCPGKey))
            {
                throw new PGPException("Version 3 OpenPGP keys can only use RSA. Found " + key.getClass().getName());
            }
            RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

            try
            {
                MessageDigest digest = helper.createMessageDigest("MD5");

                byte[] bytes = new MPInteger(rK.getModulus()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);

                bytes = new MPInteger(rK.getPublicExponent()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);

                return digest.digest();
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("can't find MD5", e);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else if (publicPk.getVersion() == PublicKeyPacket.VERSION_4)
        {
            try
            {
                byte[] kBytes = publicPk.getEncodedContents();

                MessageDigest digest = helper.createMessageDigest("SHA1");

                digest.update((byte)0x99);
                digest.update((byte)(kBytes.length >> 8));
                digest.update((byte)kBytes.length);
                digest.update(kBytes);

                return digest.digest();
            }
            catch (GeneralSecurityException e)
            {
                throw new PGPException("can't find SHA1", e);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else if (publicPk.getVersion() == PublicKeyPacket.LIBREPGP_5 || publicPk.getVersion() == PublicKeyPacket.VERSION_6)
        {
            try
            {
                byte[] kBytes = publicPk.getEncodedContents();

                MessageDigest digest = helper.createMessageDigest("SHA-256");

                digest.update((byte) (publicPk.getVersion() == PublicKeyPacket.VERSION_6 ? 0x9b : 0x9a));

                digest.update((byte)(kBytes.length >> 24));
                digest.update((byte)(kBytes.length >> 16));
                digest.update((byte)(kBytes.length >> 8));
                digest.update((byte)kBytes.length);

                digest.update(kBytes);

                return digest.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new PGPException("can't find SHA-256", e);
            }
            catch (NoSuchProviderException e)
            {
                throw new PGPException("can't find SHA-256", e);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported PGP key version: " + publicPk.getVersion());
        }
    }
}
