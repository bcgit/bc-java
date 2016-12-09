package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

// TODO[jsse] Serializable ?
class ProvExtendedSSLSession
    extends ExtendedSSLSession
{
    // TODO[jsse] Ensure this behaves according to the javadoc for SSLSocket.getSession and SSLEngine.getSession
    protected final static ProvExtendedSSLSession NULL_SESSION = new ProvExtendedSSLSession(ProvSSLSession.NULL_SESSION);

    protected final Map<String, Object> valueMap = Collections.synchronizedMap(new HashMap<String, Object>());

    private final ProvSSLSession sslSession;

    ProvExtendedSSLSession(ProvSSLSession sslSession)
    {
        this.sslSession = sslSession;
    }

    public int getApplicationBufferSize()
    {
        throw new UnsupportedOperationException();
    }

    public String getCipherSuite()
    {
        return sslSession.getCipherSuite();
    }

    public long getCreationTime()
    {
        return sslSession.getCreationTime();
    }

    public byte[] getId()
    {
        return sslSession.getId();
    }

    public long getLastAccessedTime()
    {
        return sslSession.getLastAccessedTime();
    }

    public Certificate[] getLocalCertificates()
    {
        return sslSession.getLocalCertificates();
    }

    public Principal getLocalPrincipal()
    {
        return sslSession.getLocalPrincipal();
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms()
    {
        throw new UnsupportedOperationException();
    }

    public int getPacketBufferSize()
    {
        return sslSession.getPacketBufferSize();
    }

    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException
    {
        return sslSession.getPeerCertificateChain();
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException
    {
        return sslSession.getPeerCertificates();
    }

    public String getPeerHost()
    {
        return sslSession.getPeerHost();
    }

    public int getPeerPort()
    {
        return sslSession.getPeerPort();
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException
    {
        return sslSession.getPeerPrincipal();
    }

    public String[] getPeerSupportedSignatureAlgorithms()
    {
        throw new UnsupportedOperationException();
    }

    public String getProtocol()
    {
        return sslSession.getProtocol();
    }

    // TODO: SSNIServerName post 1.7
    public List getRequestedServerNames()
    {
        throw new UnsupportedOperationException();
    }

    public SSLSessionContext getSessionContext()
    {
        return sslSession.getSessionContext();
    }

    public Object getValue(String name)
    {
        return sslSession.getValue(name);
    }

    public String[] getValueNames()
    {
        return sslSession.getValueNames();
    }

    public void invalidate()
    {
        sslSession.invalidate();
    }

    public boolean isValid()
    {
        return sslSession.isValid();
    }

    public void putValue(String name, Object value)
    {
        sslSession.putValue(name, value);
    }

    public void removeValue(String name)
    {
        sslSession.removeValue(name);
    }
}
