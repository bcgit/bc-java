package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.jsse.BCSNIServerName;

final class ImportSSLSession_5
    extends BCExtendedSSLSession
    implements ImportSSLSession
{
    final SSLSession sslSession;

    ImportSSLSession_5(SSLSession sslSession)
    {
        this.sslSession = sslSession;
    }

    public SSLSession unwrap()
    {
        return sslSession;
    }

    @Override
    public boolean equals(Object obj)
    {
        return null != obj && obj.equals(sslSession);
    }

    public int getApplicationBufferSize()
    {
        return sslSession.getApplicationBufferSize();
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
        return null;
    }

    public int getPacketBufferSize()
    {
        return sslSession.getPacketBufferSize();
    }

    @SuppressWarnings("deprecation")
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

    @Override
    public String[] getPeerSupportedSignatureAlgorithms()
    {
        return null;
    }

    public String getProtocol()
    {
        return sslSession.getProtocol();
    }

    @Override
    public List<BCSNIServerName> getRequestedServerNames()
    {
        return Collections.emptyList();
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

    @Override
    public int hashCode()
    {
        return sslSession.hashCode();
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

    @Override
    public String toString()
    {
        return sslSession.toString();
    }
}
