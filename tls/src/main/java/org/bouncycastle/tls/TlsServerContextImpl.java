package org.bouncycastle.tls;

import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.TlsCrypto;

class TlsServerContextImpl
    extends AbstractTlsContext
    implements TlsServerContext
{
    TlsServerContextImpl(TlsCrypto crypto, SecureRandom secureRandom, SecurityParameters securityParameters)
    {
        super(crypto, secureRandom, securityParameters);
    }

    public boolean isServer()
    {
        return true;
    }
}
