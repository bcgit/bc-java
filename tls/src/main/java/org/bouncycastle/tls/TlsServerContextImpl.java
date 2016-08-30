package org.bouncycastle.tls;

class TlsServerContextImpl
    extends AbstractTlsContext
    implements TlsServerContext
{
    TlsServerContextImpl(AbstractTlsCrypto crypto, SecurityParameters securityParameters)
    {
        super(crypto, securityParameters);
    }

    public boolean isServer()
    {
        return true;
    }
}
