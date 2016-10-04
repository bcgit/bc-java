package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.tls.TlsContext;
import org.bouncycastle.tls.crypto.TlsSigner;

/**
 * Base class for a signing service for use with TLS.
 */
public abstract class AbstractTlsSigner
    implements TlsSigner
{
    protected TlsContext context;

    protected AbstractTlsSigner(TlsContext context)
    {
        if (context == null)
        {
            throw new IllegalArgumentException("'context' cannot be null");
        }
        this.context = context;
    }

    public TlsContext getContext()
    {
        return context;
    }
}
