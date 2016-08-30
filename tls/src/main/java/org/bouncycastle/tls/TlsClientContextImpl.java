package org.bouncycastle.tls;

class TlsClientContextImpl
    extends AbstractTlsContext
    implements TlsClientContext
{
    TlsClientContextImpl(AbstractTlsCrypto crypto, SecurityParameters securityParameters)
    {
        super(crypto, securityParameters);
    }

    public boolean isServer()
    {
        return false;
    }
}
