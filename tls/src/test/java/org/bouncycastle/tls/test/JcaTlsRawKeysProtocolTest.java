package org.bouncycastle.tls.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;

/**
 * Runs the {@link TlsRawKeysProtocolTest} scenarios (RFC 7250) against the JCA crypto backend,
 * exercising {@code JcaTlsRawKeyCertificate}.
 */
public class JcaTlsRawKeysProtocolTest
    extends TlsRawKeysProtocolTest
{
    protected TlsCrypto createCrypto()
    {
        return new JcaTlsCryptoProvider().setProvider(new BouncyCastleProvider()).create(RANDOM);
    }
}
