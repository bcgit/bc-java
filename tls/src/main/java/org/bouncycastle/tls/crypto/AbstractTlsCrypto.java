package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.TlsContext;

public abstract class AbstractTlsCrypto implements TlsCrypto
{
    protected TlsContext context;

    public void init(TlsContext context)
    {
        this.context = context;
    }

}
