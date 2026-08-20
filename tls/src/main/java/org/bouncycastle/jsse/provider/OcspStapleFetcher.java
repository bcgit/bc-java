package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.Extensions;

/**
 * Source of the OCSP responses a server staples to its certificate chain.
 * <p/>
 * Separate from {@link OcspStapleCache} so that the caching, freshness and single-flight rules can be
 * exercised without opening a socket, and so that a source other than
 * {@link OcspStapleHttpFetcher} - responses refreshed out of band, say - can be supplied in its
 * place.
 */
interface OcspStapleFetcher
{
    /**
     * Obtain a response for one certificate.
     *
     * @param certID            identifies the certificate to the responder; also the cache key.
     * @param cert              the certificate itself, for locating a responder from its AIA
     *                          extension.
     * @param requestExtensions OCSP request extensions to include, or null for none.
     * @return the response, or null if there is nothing to staple - no responder could be located,
     *         the responder declined, or the answer could not be bound to <code>certID</code>. A
     *         null return is not an error: stapling is an optimisation and a handshake proceeds
     *         without it.
     * @throws IOException if a responder was located but could not be reached, answered over the
     *                     size limit, or returned something unparseable.
     */
    OcspStaple fetch(CertID certID, X509Certificate cert, Extensions requestExtensions)
        throws IOException;
}
