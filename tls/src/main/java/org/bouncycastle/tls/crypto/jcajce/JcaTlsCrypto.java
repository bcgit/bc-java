package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.crypto.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.bc.BcTlsSecret;

public class JcaTlsCrypto extends AbstractTlsCrypto
{
    private final JcaJceHelper helper;

    JcaTlsCrypto(JcaJceHelper helper)
    {
        this.helper = helper;
    }

    public byte[] calculateDigest(short hashAlgorithm, byte[] buf, int off, int len) throws IOException
    {
        try
        {
            MessageDigest d = createHash(hashAlgorithm);

            d.update(buf, off, len);

            return d.digest();
        }
        catch (GeneralSecurityException e)
        {
            throw new IOException("unable to calculate digest: " + e.getMessage(), e);
        }
    }

    public JceTlsSecret adoptSecret(byte[] data)
    {
        return new JceTlsSecret(this, data);
    }

    public TlsCertificate createCertificate(byte[] encoding)
        throws IOException
    {
        return new JcaTlsCertificate(encoding, helper);
    }

    public TlsCipher createCipher(int encryptionAlgorithm, int macAlgorithm) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    public TlsDHDomain createDHDomain(TlsDHConfig dhConfig)
    {
        return new JceTlsDHDomain(this, dhConfig);
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig)
    {
        return new JcaTlsECDomain(this, ecConfig);
    }

    public TlsSecret createSecret(byte[] data)
    {
        throw new UnsupportedOperationException();
    }

    public TlsSecret generateRandomSecret(int length)
    {
        throw new UnsupportedOperationException();
    }

    public TlsContext getContext()
        {
            return context;
        }

    JcaJceHelper getHelper()
    {
        return helper;
    }

    MessageDigest createHash(short hashAlgorithm)
        throws NoSuchProviderException, NoSuchAlgorithmException
    {
        String digestName;

        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            digestName = "MD5";
            break;
        case HashAlgorithm.sha1:
            digestName = "SHA-1";
            break;
        case HashAlgorithm.sha224:
            digestName = "SHA-224";
            break;
        case HashAlgorithm.sha256:
            digestName = "SHA-256";
            break;
        case HashAlgorithm.sha384:
            digestName = "SHA-384";
            break;
        case HashAlgorithm.sha512:
            digestName = "SHA-512";
            break;
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }

        return helper.createDigest(digestName);
    }
}
