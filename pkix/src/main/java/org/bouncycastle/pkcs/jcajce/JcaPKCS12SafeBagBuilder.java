package org.bouncycastle.pkcs.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCSIOException;

/**
 * JCA-aware extension of {@link PKCS12SafeBagBuilder} that accepts standard JCA
 * {@link X509Certificate} and {@link PrivateKey} inputs.
 */
public class JcaPKCS12SafeBagBuilder
    extends PKCS12SafeBagBuilder
{
    /**
     * Build a {@code certBag} from a JCA {@link X509Certificate}.
     *
     * @param certificate the certificate to wrap.
     * @throws IOException if the certificate cannot be encoded.
     */
    public JcaPKCS12SafeBagBuilder(X509Certificate certificate)
        throws IOException
    {
        super(convertCert(certificate));
    }

    private static Certificate convertCert(X509Certificate certificate)
        throws IOException
    {
        try
        {
            return Certificate.getInstance(certificate.getEncoded());
        }
        catch (CertificateEncodingException e)
        {
            throw new PKCSIOException("cannot encode certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Build a {@code pkcs8ShroudedKeyBag} by encrypting the supplied JCA {@link PrivateKey}.
     *
     * @param privateKey the private key to wrap.
     * @param encryptor  the password-based output encryptor used to protect the key.
     */
    public JcaPKCS12SafeBagBuilder(PrivateKey privateKey, OutputEncryptor encryptor)
    {
        super(PrivateKeyInfo.getInstance(privateKey.getEncoded()), encryptor);
    }

    /**
     * Build a {@code keyBag} from a JCA {@link PrivateKey} (no encryption).
     *
     * @param privateKey the private key payload.
     */
    public JcaPKCS12SafeBagBuilder(PrivateKey privateKey)
    {
        super(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
    }
}
