package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.TlsSession;

class ProvSSLSession
    extends ProvSSLSessionBase
{
    // TODO[jsse] Ensure this behaves according to the javadoc for SSLSocket.getSession and SSLEngine.getSession
    protected final static ProvSSLSession NULL_SESSION = new ProvSSLSession(null, null, -1, null);

    protected final TlsSession tlsSession;
    protected final SessionParameters sessionParameters;

    ProvSSLSession(ProvSSLSessionContext sslSessionContext, String peerHost, int peerPort, TlsSession tlsSession)
    {
        super(sslSessionContext, peerHost, peerPort);

        this.tlsSession = tlsSession;
        this.sessionParameters = tlsSession == null ? null : tlsSession.exportSessionParameters();
    }

    @Override
    protected byte[] getIDArray()
    {
        return (null == tlsSession) ? null : tlsSession.getSessionID();
    }

    TlsSession getTlsSession()
    {
        return tlsSession;
    }

    public String getCipherSuite()
    {
        return sessionParameters == null
            ?   "TLS_NULL_WITH_NULL_NULL"
            :   sslSessionContext.getSSLContext().getCipherSuiteString(sessionParameters.getCipherSuite());
    }

    public Certificate[] getLocalCertificates()
    {
        if (sessionParameters != null)
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(sslSessionContext.getCrypto(), sessionParameters.getLocalCertificate());
            if (chain != null && chain.length > 0)
            {
                return chain;
            }
        }

        return null;
    }

    public Principal getLocalPrincipal()
    {
        return sessionParameters == null
            ?   null
            :   JsseUtils.getSubject(sslSessionContext.getCrypto(), sessionParameters.getLocalCertificate());
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException
    {
        if (sessionParameters != null)
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(sslSessionContext.getCrypto(), sessionParameters.getPeerCertificate());
            if (chain != null && chain.length > 0)
            {
                return chain;
            }
        }

        throw new SSLPeerUnverifiedException("No peer identity established");
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException
    {
        if (sessionParameters != null)
        {
            X500Principal principal = JsseUtils.getSubject(sslSessionContext.getCrypto(), sessionParameters.getPeerCertificate());
            if (principal != null)
            {
                return principal;
            }
        }

        throw new SSLPeerUnverifiedException("No peer identity established");
    }

    public String getProtocol()
    {
        return sessionParameters == null
            ?   null
            :   sslSessionContext.getSSLContext().getProtocolString(sessionParameters.getNegotiatedVersion());
    }

    public void invalidate()
    {
        if (tlsSession != null)
        {
            tlsSession.invalidate();
        }
    }

    public boolean isValid()
    {
        return tlsSession != null && tlsSession.isResumable();
    }
}
