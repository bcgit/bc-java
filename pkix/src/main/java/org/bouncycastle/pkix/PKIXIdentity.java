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

    /**
     * Base constructor - a private key and its associated certificate chain. The chain
     * should be ordered so that certificateHolders[0] is the matching public key for privKey.
     *
     * @param privateKeyInfo the private key.
     * @param certificateHolders the public key certificates identifying it.
     */
    public PKIXIdentity(PrivateKeyInfo privateKeyInfo, X509CertificateHolder[] certificateHolders)
    {
        this.privateKeyInfo = privateKeyInfo;
        this.certificateHolders = new X509CertificateHolder[certificateHolders.length];
        System.arraycopy(certificateHolders, 0, this.certificateHolders, 0, certificateHolders.length);
    }

    /**
     * Base constructor - a private key and its associated public key certificate.
     *
     * @param privateKeyInfo the private key.
     * @param certHolder privKey's matching public key certificate.
     */
    public PKIXIdentity(PrivateKeyInfo privateKeyInfo, X509CertificateHolder certHolder)
    {
        this(privateKeyInfo, new X509CertificateHolder[] { certHolder });
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
     * Return the certificate chain associated with the private key info.
     *
     * @return the certificate chain.
     */
    public X509CertificateHolder[] getCertificateChain()
    {
        X509CertificateHolder[] rv = new X509CertificateHolder[certificateHolders.length];

        System.arraycopy(certificateHolders, 0, rv, 0, rv.length);

        return rv;
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
