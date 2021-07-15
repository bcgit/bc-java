package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Base class for a TlsCrypto implementation that provides some needed methods from elsewhere in the impl package.
 */
public abstract class AbstractTlsCrypto
    implements TlsCrypto
{
    public TlsSecret adoptSecret(TlsSecret secret)
    {
        // TODO[tls] Need an alternative that doesn't require AbstractTlsSecret (which holds literal data)
        if (secret instanceof AbstractTlsSecret)
        {
            AbstractTlsSecret sec = (AbstractTlsSecret)secret;

            return createSecret(sec.copyData());
        }

        throw new IllegalArgumentException("unrecognized TlsSecret - cannot copy data: " + secret.getClass().getName());
    }
}
