package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.TlsContext;

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
