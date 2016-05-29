package org.bouncycastle.tls;

import java.security.SecureRandom;

import org.bouncycastle.tls.crypto.TlsCrypto;

class TlsClientContextImpl
    extends AbstractTlsContext
    implements TlsClientContext
{
    TlsClientContextImpl(TlsCrypto crypto, SecureRandom secureRandom, SecurityParameters securityParameters)
    {
        super(crypto, secureRandom, securityParameters);
    }

    public boolean isServer()
    {
        return false;
    }
}
