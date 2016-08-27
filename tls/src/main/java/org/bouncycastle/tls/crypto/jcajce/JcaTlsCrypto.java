package org.bouncycastle.tls.crypto.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.TlsHash;
import org.bouncycastle.tls.crypto.AbstractTlsCrypto;
import org.bouncycastle.tls.crypto.NonceRandomGenerator;
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
            MessageDigest d = createMessageDigest(hashAlgorithm);

            d.update(buf, off, len);

            return d.digest();
        }
        catch (IllegalArgumentException e)
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

    @Override
    public TlsHash createHash(SignatureAndHashAlgorithm sidAlgorithm)
    {
        return null;
    }

    @Override
    public TlsHash createHash(short algorithm)
    {
        return null;
    }

    public TlsContext getContext()
        {
            return context;
        }

    JcaJceHelper getHelper()
    {
        return helper;
    }


    public TlsHash createMessageDigest(SignatureAndHashAlgorithm signatureAndHashAlgorithm)
    {
        final MessageDigest d = signatureAndHashAlgorithm == null ? new CombinedHash() : createMessageDigest(signatureAndHashAlgorithm.getHash());

        return new TlsHash()
        {
            @Override
            public void update(byte[] data, int offSet, int length)
            {
               d.update(data, offSet, length);
            }

            @Override
            public byte[] calculateHash()
            {
                return d.digest();
            }

            @Override
            public TlsHash cloneHash()
            {
                return null;
            }

            @Override
            public void reset()
            {
                d.reset();
            }
        };
    }

    @Override
    public NonceRandomGenerator createNonceRandomGenerator()
    {
        return null;
    }

    MessageDigest createMessageDigest(short hashAlgorithm)
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

        try
        {
            return helper.createDigest(digestName);
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalArgumentException("unable to create message digest:" + e.getMessage(), e);
        }
    }

    private class CombinedHash
        extends MessageDigest
    {

        protected CombinedHash()
        {
            super("MD5andSHA1");
        }

        @Override
        protected void engineUpdate(byte b)
        {

        }

        @Override
        protected void engineUpdate(byte[] bytes, int i, int i1)
        {

        }

        @Override
        protected byte[] engineDigest()
        {
            return new byte[0];
        }

        @Override
        protected void engineReset()
        {

        }
    }
}
