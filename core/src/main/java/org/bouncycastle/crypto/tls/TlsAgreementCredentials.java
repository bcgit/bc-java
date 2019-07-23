package org.bouncycastle.crypto.tls;

import java.io.IOException;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public interface TlsAgreementCredentials
    extends TlsCredentials
{
    byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey)
        throws IOException;
}
