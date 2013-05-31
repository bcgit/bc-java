package org.bouncycastle.crypto.tls;

public abstract class AbstractTlsSigner
    implements TlsSigner
{

    protected TlsContext context;

    public void init(TlsContext context)
    {
        this.context = context;
    }
}
