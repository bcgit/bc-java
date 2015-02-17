package org.bouncycastle.jce.provider;

import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.x509.X509AttributeCertificate;

class PrincipalUtils
{
    static X500Name getSubjectPrincipal(X509Certificate cert)
    {
        return X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
    }

    static X500Name getIssuerPrincipal(X509CRL crl)
    {
        return X500Name.getInstance(crl.getIssuerX500Principal().getEncoded());
    }

    static X500Name getIssuerPrincipal(X509Certificate cert)
    {
        return X500Name.getInstance(cert.getIssuerX500Principal().getEncoded());
    }

    static X500Name getCA(TrustAnchor trustAnchor)
    {
        return X500Name.getInstance(trustAnchor.getCA().getEncoded());
    }

    /**
     * Returns the issuer of an attribute certificate or certificate.
     *
     * @param cert The attribute certificate or certificate.
     * @return The issuer as <code>X500Principal</code>.
     */
    static X500Name getEncodedIssuerPrincipal(
        Object cert)
    {
        if (cert instanceof X509Certificate)
        {
            return getIssuerPrincipal((X509Certificate)cert);
        }
        else
        {
            return X500Name.getInstance(((X500Principal)((X509AttributeCertificate)cert).getIssuer().getPrincipals()[0]).getEncoded());
        }
    }
}
