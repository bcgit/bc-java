package org.bouncycastle.x509;

import org.bouncycastle.jce.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.io.IOException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509AttributeCertificate;

class PrincipalUtils
{
    static X500Name getSubjectPrincipal(X509Certificate cert)
    {
        try
        {
            TBSCertificateStructure tbsCert = TBSCertificateStructure.getInstance(cert.getTBSCertificate());

            return X500Name.getInstance(tbsCert.getSubject());
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.toString());
        }
    }

    static X500Name getIssuerPrincipal(X509CRL crl)
    {
        try
        {
            TBSCertList tbsCertList = TBSCertList.getInstance(crl.getTBSCertList());

            return X500Name.getInstance(tbsCertList.getIssuer());
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.toString());
        }
    }

    static X500Name getIssuerPrincipal(X509Certificate cert)
    {
        try
        {
            TBSCertificateStructure tbsCert = TBSCertificateStructure.getInstance(cert.getTBSCertificate());

            return X500Name.getInstance(tbsCert.getIssuer());
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e.toString());
        }
    }

    static X500Name getCA(TrustAnchor trustAnchor)
    {
        return new X500Name(trustAnchor.getCAName());
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
            return X500Name.getInstance(((X509Principal)((X509AttributeCertificate)cert).getIssuer().getPrincipals()[0]).getEncoded());
        }
    }
}
