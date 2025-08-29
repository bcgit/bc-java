package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.TlsSession;

class ProvSSLSessionResumed
    extends ProvSSLSessionHandshake
{
    protected final TlsSession tlsSession;
    protected final SessionParameters sessionParameters;
    protected final JsseSessionParameters jsseSessionParameters;
    protected final long lastAccessedTime;

    ProvSSLSessionResumed(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort,
        SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters,
        ProvSSLSession resumedSession)
    {
        super(sslSessionContext, resumedSession.getValueMap(), peerHost, peerPort, resumedSession.getCreationTime(),
            securityParameters, jsseSecurityParameters);

        this.tlsSession = resumedSession.getTlsSession();
        this.sessionParameters = tlsSession.exportSessionParameters();
        this.jsseSessionParameters = resumedSession.getJsseSessionParameters();
        this.lastAccessedTime = resumedSession.access();
    }

    @Override
    protected int getCipherSuiteTLS()
    {
        return sessionParameters.getCipherSuite();
    }

    @Override
    protected byte[] getIDArray()
    {
        return tlsSession.getSessionID();
    }

    public long getLastAccessedTime()
    {
        return lastAccessedTime;
    }

    @Override
    protected JsseSessionParameters getJsseSessionParameters()
    {
        return jsseSessionParameters;
    }

    @Override
    protected org.bouncycastle.tls.Certificate getLocalCertificateTLS()
    {
        return sessionParameters.getLocalCertificate();
    }

    @Override
    protected org.bouncycastle.tls.Certificate getPeerCertificateTLS()
    {
        return sessionParameters.getPeerCertificate();
    }

    @Override
    protected ProtocolVersion getProtocolTLS()
    {
        return sessionParameters.getNegotiatedVersion();
    }

    @Override
    protected void invalidateTLS()
    {
        tlsSession.invalidate();
    }

    public boolean isValid()
    {
        return super.isValid() && tlsSession.isResumable();
    }
}
