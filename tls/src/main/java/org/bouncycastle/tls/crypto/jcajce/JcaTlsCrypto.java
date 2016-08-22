package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.crypto.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsCipher;
import org.bouncycastle.tls.crypto.TlsDHConfig;
import org.bouncycastle.tls.crypto.TlsDHDomain;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsECDomain;
import org.bouncycastle.tls.crypto.TlsSecret;

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
        throw new UnsupportedOperationException();
    }

    public TlsECDomain createECDomain(TlsECConfig ecConfig)
    {
        throw new UnsupportedOperationException();
    }

    public TlsSecret createSecret(byte[] data)
    {
        throw new UnsupportedOperationException();
    }

    public TlsSecret generateRandomSecret(int length)
    {
        throw new UnsupportedOperationException();
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
