package org.bouncycastle.jce.provider;

import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.x509.X509AttributeCertificate;

class PrincipalUtils
{
    static X500Name getCA(TrustAnchor trustAnchor)
    {
        return getX500Name(notNull(trustAnchor).getCA());
    }

    /**
     * Returns the issuer of an attribute certificate or certificate.
     *
     * @param cert The attribute certificate or certificate.
     * @return The issuer as <code>X500Principal</code>.
     */
    static X500Name getEncodedIssuerPrincipal(Object cert)
    {
        if (cert instanceof X509Certificate)
        {
            return getIssuerPrincipal((X509Certificate)cert);
        }
        else
        {
            return getX500Name((X500Principal)((X509AttributeCertificate)cert).getIssuer().getPrincipals()[0]);
        }
    }

    static X500Name getIssuerPrincipal(X509Certificate certificate)
    {
        if (certificate instanceof BCX509Certificate)
        {
            return notNull(((BCX509Certificate)certificate).getIssuerX500Name());
        }
        return getX500Name(notNull(certificate).getIssuerX500Principal());
    }

    static X500Name getIssuerPrincipal(X509CRL crl)
    {
        return getX500Name(notNull(crl).getIssuerX500Principal());
    }

    static X500Name getSubjectPrincipal(X509Certificate certificate)
    {
        if (certificate instanceof BCX509Certificate)
        {
            return notNull(((BCX509Certificate)certificate).getSubjectX500Name());
        }
        return getX500Name(notNull(certificate).getSubjectX500Principal());
    }

    static X500Name getX500Name(X500Principal principal)
    {
        X500Name name = X500Name.getInstance(getEncoded(principal));
        return notNull(name);
    }

    static X500Name getX500Name(X500NameStyle style, X500Principal principal)
    {
        X500Name name = X500Name.getInstance(style, getEncoded(principal));
        return notNull(name);
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
