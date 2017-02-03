package org.bouncycastle.est;


import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * Implementations of this are to examine the chain in conjunction with the authType
 * and  throw some sort of exception or allow the method to complete.
 */
public interface TLSAuthorizer<T>
{
    void authorize(Set<TrustAnchor> acceptedIssuers, X509Certificate[] chain, String authType)
        throws CertificateException;
}
