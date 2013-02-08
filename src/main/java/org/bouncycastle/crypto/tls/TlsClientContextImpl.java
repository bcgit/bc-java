package org.bouncycastle.crypto.tls;

import java.security.SecureRandom;

class TlsClientContextImpl implements TlsClientContext
{
    private SecureRandom secureRandom;
    private SecurityParameters securityParameters;

    private ProtocolVersion clientVersion = null;
    private ProtocolVersion serverVersion = null;
    private Object userObject = null;

    TlsClientContextImpl(SecureRandom secureRandom, SecurityParameters securityParameters)
    {
        this.secureRandom = secureRandom;
        this.securityParameters = securityParameters;
    }

    public SecureRandom getSecureRandom()
    {
        return secureRandom;
    }

    public SecurityParameters getSecurityParameters()
    {
        return securityParameters;
    }

    public ProtocolVersion getClientVersion()
    {
        return clientVersion;
    }

    public void setClientVersion(ProtocolVersion clientVersion)
    {
        this.clientVersion = clientVersion;
    }

    public ProtocolVersion getServerVersion()
    {
        return serverVersion;
    }

    public void setServerVersion(ProtocolVersion serverVersion)
    {
        this.serverVersion = serverVersion;
    }

    public Object getUserObject()
    {
        return userObject;
    }

    public void setUserObject(Object userObject)
    {
        this.userObject = userObject;
    }
}
