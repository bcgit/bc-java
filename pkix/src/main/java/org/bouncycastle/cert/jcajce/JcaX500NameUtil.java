package org.bouncycastle.cert.jcajce;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;

public class JcaX500NameUtil
{
    public static X500Name getIssuer(X509Certificate certificate)
    {
        if (certificate instanceof BCX509Certificate)
        {
            return notNull(((BCX509Certificate)certificate).getIssuerX500Name());
        }
        return getX500Name(certificate.getIssuerX500Principal());
    }

    public static X500Name getIssuer(X500NameStyle style, X509Certificate certificate)
    {
        if (certificate instanceof BCX509Certificate)
        {
            return X500Name.getInstance(style, notNull(((BCX509Certificate)certificate).getIssuerX500Name()));
        }
        return getX500Name(style, certificate.getIssuerX500Principal());
    }

    public static X500Name getSubject(X509Certificate certificate)
    {
        if (certificate instanceof BCX509Certificate)
        {
            return notNull(((BCX509Certificate)certificate).getSubjectX500Name());
        }
        return getX500Name(certificate.getSubjectX500Principal());
    }

    public static X500Name getSubject(X500NameStyle style, X509Certificate certificate)
    {
        if (certificate instanceof BCX509Certificate)
        {
            return X500Name.getInstance(style, notNull(((BCX509Certificate)certificate).getSubjectX500Name()));
        }
        return getX500Name(style, certificate.getSubjectX500Principal());
    }

    public static X500Name getX500Name(X500Principal principal)
    {
        return X500Name.getInstance(getEncoded(principal));
    }

    public static X500Name getX500Name(X500NameStyle style, X500Principal principal)
    {
        return X500Name.getInstance(style, getEncoded(principal));
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

    private static byte[] getEncoded(X500Principal principal)
    {
        return notNull(principal).getEncoded();
    }
}
