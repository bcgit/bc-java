package org.bouncycastle.est;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;

import javax.security.cert.X509Certificate;

/**
 * RFC7030BootstrapAuthorizer implementations will be called
 * to provide explicit acceptance of caCerts in the event that the
 * TLS connection cannot be verified.
 *
 * It needs to be used in conjunction with a permissive TLSAuthorizer<T>
 * and is called after the cacerts have been fetched from the server.
 *
 */
public interface RFC7030BootstrapAuthorizer<T>
{
    /**
     * Examine serverCertificates and the caCerts from the EST server and if they cannot be authorised
     * throw an exception.
     *
     * @param caCerts            The CaCerts from the 'cacerts' request.
     * @param serverCertificates The server certificates supplied during TLS handshake by the server.
     * @throws Exception if authorisation can not be given.
     */
    void authorise(Store<X509CertificateHolder> caCerts, X509Certificate[] serverCertificates, T session)
        throws Exception;
}
