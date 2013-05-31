package org.bouncycastle.cert.jcajce;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.jce.PrincipalUtil;

public class JcaX500NameUtil
{
    public static X500Name getIssuer(X509Certificate certificate)
    {
try
{
        return X500Name.getInstance(PrincipalUtil.getIssuerX509Principal(certificate).getEncoded());
}
catch (Exception e)
{
   throw new IllegalStateException(e.toString());
}
    }

    public static X500Name getSubject(X509Certificate certificate)
    {
try
{
        return X500Name.getInstance(PrincipalUtil.getSubjectX509Principal(certificate).getEncoded());
}
catch (Exception e)
{
   throw new IllegalStateException(e.toString());
}
    }

    public static X500Name getIssuer(X500NameStyle style, X509Certificate certificate)
    {
try
{
        return X500Name.getInstance(style, PrincipalUtil.getIssuerX509Principal(certificate).getEncoded());
}
catch (Exception e)
{
   throw new IllegalStateException(e.toString());
}
    }

    public static X500Name getSubject(X500NameStyle style, X509Certificate certificate)
    {
try
{
        return X500Name.getInstance(style, PrincipalUtil.getSubjectX509Principal(certificate).getEncoded());
}
catch (Exception e)
{
   throw new IllegalStateException(e.toString());
}
    }
}
