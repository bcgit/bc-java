package org.bouncycastle.jce.provider;

import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
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
        return new X500Name(RFC4519Style.INSTANCE, trustAnchor.getCAName());
    }

    static X500Name getX500Name(X500Principal principal)
    {
        X500Name name = X500Name.getInstance(getEncoded(principal));
        return notNull(name);
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

    private static byte[] getEncoded(X500Principal principal)
     {
         byte[] encoding = notNull(principal).getEncoded();
         return notNull(encoding);
     }

     private static byte[] notNull(byte[] encoding)
     {
         if (null == encoding)
         {
             throw new IllegalStateException();
         }
         return encoding;
     }

     private static TrustAnchor notNull(TrustAnchor trustAnchor)
     {
         if (null == trustAnchor)
         {
             throw new IllegalStateException();
         }
         return trustAnchor;
     }

     private static X509Certificate notNull(X509Certificate certificate)
     {
         if (null == certificate)
         {
             throw new IllegalStateException();
         }
         return certificate;
     }

     private static X509CRL notNull(X509CRL crl)
     {
         if (null == crl)
         {
             throw new IllegalStateException();
         }
         return crl;
     }

     private static X500Name notNull(X500Name name)
     {
         if (null == name)
         {
             throw new IllegalStateException();
         }
         return name;
     }

     private static X500Principal notNull(X500Principal principal)
     {
         if (null == principal)
         {
             throw new IllegalStateException();
         }
         return principal;
     }
}
