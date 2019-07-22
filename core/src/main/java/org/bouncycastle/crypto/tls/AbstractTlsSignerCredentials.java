package org.bouncycastle.crypto.tls;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public abstract class AbstractTlsSignerCredentials
    extends AbstractTlsCredentials
    implements TlsSignerCredentials
{
    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm()
    {
        throw new IllegalStateException("TlsSignerCredentials implementation does not support (D)TLS 1.2+");
    }
}
