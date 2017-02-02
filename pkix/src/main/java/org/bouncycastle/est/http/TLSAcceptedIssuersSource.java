package org.bouncycastle.est.http;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * TLSAcceptedIssuersSource provides an array of X509Certificates that
 * are to be accepted as issuers.
 */
public interface TLSAcceptedIssuersSource
{
    Set<TrustAnchor> anchors();
}
