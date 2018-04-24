package org.bouncycastle.tls;

import java.io.IOException;

/**
 * Base interface to provide TLS authentication credentials.
 */
public interface TlsAuthentication
{
    /**
     * Called by the protocol handler to report the server certificate
     * Note: this method is responsible for certificate verification and validation
     *
     * @param serverCertificate the server certificate received
     * @throws IOException
     */
    void notifyServerCertificate(TlsServerCertificate serverCertificate)
        throws IOException;

    /**
     * Return client credentials in response to server's certificate request. The returned value may
     * be null, or else it MUST implement <em>exactly one</em> of {@link TlsCredentialedAgreement},
     * {@link TlsCredentialedDecryptor}, or {@link TlsCredentialedSigner}, depending on the key
     * exchange that was negotiated and the details of the {@link CertificateRequest}.
     *
     * @param certificateRequest
     *            details of the certificate request
     * @return a TlsCredentials object or null for no client authentication
     * @throws IOException
     */
    TlsCredentials getClientCredentials(CertificateRequest certificateRequest)
        throws IOException;
}
