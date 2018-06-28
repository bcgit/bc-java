package org.bouncycastle.openssl;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;

/**
 * Holder for an OpenSSL trusted certificate block.
 */
public class X509TrustedCertificateBlock
{
    private final X509CertificateHolder certificateHolder;
    private final CertificateTrustBlock trustBlock;

    public X509TrustedCertificateBlock(X509CertificateHolder certificateHolder, CertificateTrustBlock trustBlock)
    {
        this.certificateHolder = certificateHolder;
        this.trustBlock = trustBlock;
    }

    public X509TrustedCertificateBlock(byte[] encoding)
        throws IOException
    {
        ASN1InputStream aIn = new ASN1InputStream(encoding);

        this.certificateHolder = new X509CertificateHolder(aIn.readObject().getEncoded());

        ASN1Object tBlock = aIn.readObject();

        if (tBlock != null)
        {
            this.trustBlock = new CertificateTrustBlock(tBlock.getEncoded());
        }
        else
        {
            this.trustBlock = null;
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        return Arrays.concatenate(certificateHolder.getEncoded(), trustBlock.toASN1Sequence().getEncoded());
    }

    /**
     * Return the certificate associated with this Trusted Certificate
     *
     * @return the certificate holder.
     */
    public X509CertificateHolder getCertificateHolder()
    {
        return certificateHolder;
    }

    /**
     * Return the trust block associated with this Trusted Certificate
     *
     * @return the trust block.
     */
    public CertificateTrustBlock getTrustBlock()
    {
        return trustBlock;
    }
}
