package org.bouncycastle.jsse.provider;

import java.util.List;

import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.TlsSession;

class ProvSSLSession
    extends ProvSSLSessionBase
{
    // TODO[jsse] Ensure this behaves according to the javadoc for SSLSocket.getSession and SSLEngine.getSession
    static final ProvSSLSession NULL_SESSION = new ProvSSLSession(null, null, -1, null,
        new JsseSessionParameters(null));

    protected final TlsSession tlsSession;
    protected final SessionParameters sessionParameters;
    protected final JsseSessionParameters jsseSessionParameters;

    ProvSSLSession(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort, TlsSession tlsSession,
        JsseSessionParameters jsseSessionParameters)
    {
        super(sslSessionContext, peerHost, peerPort);

        this.tlsSession = tlsSession;
        this.sessionParameters = tlsSession == null ? null : tlsSession.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters;
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
    protected JsseSessionParameters getJsseSessionParameters()
    {
        return jsseSessionParameters;
    }

    @Override
    protected org.bouncycastle.tls.Certificate getLocalCertificateTLS()
    {
        return null == sessionParameters ? null : sessionParameters.getLocalCertificate();
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    protected org.bouncycastle.tls.Certificate getPeerCertificateTLS()
    {
        return null == sessionParameters ? null : sessionParameters.getPeerCertificate();
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms()
    {
        throw new UnsupportedOperationException();
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

    public void invalidate()
    {
        super.invalidate();

        if (null != tlsSession)
        {
            tlsSession.invalidate();
        }
    }

    public boolean isValid()
    {
        return super.isValid() && null != tlsSession && tlsSession.isResumable();
    }
}
