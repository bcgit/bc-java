package org.bouncycastle.crypto.tls;

import org.bouncycastle.util.Arrays;

class TlsSessionImpl implements TlsSession
{
    byte[] sessionID;
    SecurityParameters securityParameters;

    TlsSessionImpl(byte[] sessionID, SecurityParameters securityParameters)
    {
        if (sessionID == null)
        {
            throw new IllegalArgumentException("'sessionID' cannot be null");
        }

        this.sessionID = Arrays.clone(sessionID);

        if (securityParameters != null)
        {
            this.securityParameters = new SecurityParameters();
            this.securityParameters.copySessionParametersFrom(securityParameters);
        }
    }

    public void close()
    {
        this.sessionID = null;

        if (this.securityParameters != null)
        {
            this.securityParameters.clear();
            this.securityParameters = null;
        }
    }

    public byte[] getSessionID()
    {
        return sessionID;
    }

    public SecurityParameters getSecurityParameters()
    {
        return securityParameters;
    }
}
