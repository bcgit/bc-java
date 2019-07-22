package org.bouncycastle.crypto.tls;

import java.io.IOException;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public interface TlsSignerCredentials
    extends TlsCredentials
{
    byte[] generateCertificateSignature(byte[] hash)
        throws IOException;

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();
}
