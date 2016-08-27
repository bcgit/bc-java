package org.bouncycastle.tls.crypto.bc;

import org.bouncycastle.tls.TlsContext;

public abstract class AbstractTlsSigner
    implements TlsSigner
{
    protected TlsContext context;

    public void init(TlsContext context)
    {
        this.context = context;
    }
}
