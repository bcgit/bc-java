package org.bouncycastle.tls;

/**
 * Base interface for interfaces/classes carrying TLS credentials.
 */
public interface TlsCredentials
{
    /**
     * Return the certificate structure representing our identity.
     *
     * @return our certificate structure.
     */
    Certificate getCertificate();
}
