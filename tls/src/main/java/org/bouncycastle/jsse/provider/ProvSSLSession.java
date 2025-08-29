package org.bouncycastle.jsse.provider;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.TlsSession;

class ProvSSLSession
    extends ProvSSLSessionBase
{
    protected final TlsSession tlsSession;
    protected final SessionParameters sessionParameters;
    protected final JsseSessionParameters jsseSessionParameters;
    protected final AtomicLong lastAccessedTime;

    ProvSSLSession(ProvSSLSessionContext sslSessionContext, ConcurrentHashMap<String, Object> valueMap, String peerHost,
        int peerPort, long creationTime, TlsSession tlsSession, JsseSessionParameters jsseSessionParameters)
    {
        super(sslSessionContext, valueMap, peerHost, peerPort, creationTime);

        this.tlsSession = tlsSession;
        this.sessionParameters = tlsSession == null ? null : tlsSession.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters;
        this.lastAccessedTime = new AtomicLong(creationTime);
    }

    long access()
    {
        long accessTime = getCurrentTime(), previous;
        do
        {
            previous = lastAccessedTime.get();
        }
        while (accessTime > previous && !lastAccessedTime.compareAndSet(previous, accessTime));
        return accessTime;
    }

    @Override
    protected int getCipherSuiteTLS()
    {
        return null == sessionParameters ? CipherSuite.TLS_NULL_WITH_NULL_NULL : sessionParameters.getCipherSuite();
    }

    @Override
    protected byte[] getIDArray()
    {
        return null == tlsSession ? null : tlsSession.getSessionID();
    }

    @Override
    protected JsseSecurityParameters getJsseSecurityParameters()
    {
        return null;
    }

    @Override
    protected JsseSessionParameters getJsseSessionParameters()
    {
        return jsseSessionParameters;
    }

    public long getLastAccessedTime()
    {
        return lastAccessedTime.get();
    }

    @Override
    protected org.bouncycastle.tls.Certificate getLocalCertificateTLS()
    {
        return null == sessionParameters ? null : sessionParameters.getLocalCertificate();
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms()
    {
        // TODO Should we store these in SessionParameters?
        return null;
    }

    @Override
    protected org.bouncycastle.tls.Certificate getPeerCertificateTLS()
    {
        return null == sessionParameters ? null : sessionParameters.getPeerCertificate();
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms()
    {
        // TODO Should we store these in SessionParameters?
        return null;
    }

    @Override
    protected ProtocolVersion getProtocolTLS()
    {
        return null == sessionParameters ? null : sessionParameters.getNegotiatedVersion();
    }

    @Override
    public List<BCSNIServerName> getRequestedServerNames()
    {
        throw new UnsupportedOperationException();
    }

    TlsSession getTlsSession()
    {
        return tlsSession;
    }

    @Override
    protected void invalidateTLS()
    {
        if (null != tlsSession)
        {
            tlsSession.invalidate();
        }
    }

    public boolean isValid()
    {
        return super.isValid() && null != tlsSession && tlsSession.isResumable();
    }

    static final ProvSSLSession createDummySession()
    {
        // NB: Allow session value binding on failed connections for SunJSSE compatibility 
        return new ProvSSLSession(null, createValueMap(), null, -1, getCurrentTime(), null,
            new JsseSessionParameters(null, null));
    }
}
