package com.github.gv2011.bcasn.crypto.tls;

import java.security.SecureRandom;

class TlsServerContextImpl
    extends AbstractTlsContext
    implements TlsServerContext
{
    TlsServerContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters)
    {
        super(secureRandom, securityParameters);
    }

    public boolean isServer()
    {
        return true;
    }
}
