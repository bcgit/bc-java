package org.bouncycastle.pkix;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.RecipientId;

/**
 * Holder class for public/private key based identity information.
 */
public class PKIXIdentity
{
    private final PrivateKeyInfo privateKeyInfo;
    private final X509CertificateHolder[] certificateHolders;

    public PKIXIdentity(PrivateKeyInfo privateKeyInfo, X509CertificateHolder[] certificateHolders)
    {
        this.privateKeyInfo = privateKeyInfo;
        this.certificateHolders = new X509CertificateHolder[certificateHolders.length];
        System.arraycopy(certificateHolders, 0, this.certificateHolders, 0, certificateHolders.length);
    }

    /**
     * Return the private key info for this identity.
     *
     * @return the identity's private key (if available, null otherwise).
     */
    public PrivateKeyInfo getPrivateKeyInfo()
    {
        return privateKeyInfo;
    }

    /**
     * Return the certificate associated with the private key info.
     *
     * @return a X509CertificateHolder
     */
    public X509CertificateHolder getCertificate()
    {
        return certificateHolders[0];
    }

    /**
     * Return a RecipientId for the identity's (private key, certificate) pair.
     */
    public RecipientId getRecipientId()
    {
        // TODO: handle key agreement
        return new KeyTransRecipientId(certificateHolders[0].getIssuer(), certificateHolders[0].getSerialNumber(), getSubjectKeyIdentifier());
    }

    private byte[] getSubjectKeyIdentifier()
    {
        SubjectKeyIdentifier subId = SubjectKeyIdentifier.fromExtensions(certificateHolders[0].getExtensions());

        if (subId == null)
        {
            return null;
        }

        return subId.getKeyIdentifier();
    }
}
