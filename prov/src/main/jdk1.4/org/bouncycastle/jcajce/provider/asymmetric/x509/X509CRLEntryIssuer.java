package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.X509CRLEntry;

import javax.security.auth.x500.X500Principal;

/**
 * NOTE: this class exists only in the jdk1.4 tree. X509CRLEntry.getCertificateIssuer() arrived in
 * Java 5, so the jdk1.4 cert path validators reach the certificate issuer of an indirect CRL entry
 * through this class instead, which can see the package-private entry class the BC CertificateFactory
 * produces. It is excluded from the jdk1.3 build, whose validators do not use it.
 */
public class X509CRLEntryIssuer
{
    /**
     * Return the issuer of the certificate an entry of an indirect CRL applies to.
     *
     * @param entry an entry of a CRL created by the BC provider.
     * @return the issuer, or null if the entry applies to the CRL issuer's own certificates.
     * @throws IllegalArgumentException if the entry was not created by the BC provider, as its
     * certificate issuer cannot then be determined on Java 1.4.
     */
    public static X500Principal getCertificateIssuer(X509CRLEntry entry)
    {
        if (entry instanceof X509CRLEntryObject)
        {
            return ((X509CRLEntryObject)entry).getCertificateIssuer();
        }
        if (entry instanceof org.bouncycastle.jce.provider.X509CRLEntryObject)
        {
            return ((org.bouncycastle.jce.provider.X509CRLEntryObject)entry).getCertificateIssuer();
        }

        throw new IllegalArgumentException("certificate issuer of " + entry.getClass().getName() + " cannot be determined");
    }
}
