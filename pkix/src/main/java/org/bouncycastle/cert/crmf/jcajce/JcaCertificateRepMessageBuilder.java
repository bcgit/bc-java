package org.bouncycastle.cert.crmf.jcajce;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRepMessageBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * X509Certificate aware extension of {@link CertificateRepMessageBuilder}.
 */
public class JcaCertificateRepMessageBuilder
    extends CertificateRepMessageBuilder
{
    /**
     * Base constructor which can accept 0 or more certificates representing the CA plus its chain.
     *
     * @param caCertificates the CA public key and it's support certificates (optional)
     * @throws CertificateEncodingException if the certificates cannot be re-encoded.
     */
    public JcaCertificateRepMessageBuilder(X509Certificate... caCertificates)
        throws CertificateEncodingException
    {
        super(convert(caCertificates));
    }

    private static X509CertificateHolder[] convert(X509Certificate... certificates)
        throws CertificateEncodingException
    {
        X509CertificateHolder[] certs = new X509CertificateHolder[certificates.length];
        for (int i = 0; i != certs.length; i++)
        {
            certs[i] = new JcaX509CertificateHolder(certificates[i]);
        }

        return certs;
    }
}
