package org.bouncycastle.jsse.provider;


import java.security.Principal;
import java.security.cert.Certificate;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

class ProvSSLSession
    implements SSLSession
{
    public byte[] getId()
    {
        return new byte[0];
    }

    public SSLSessionContext getSessionContext()
    {
        return null;
    }

    public long getCreationTime()
    {
        return 0;
    }

    public long getLastAccessedTime()
    {
        return 0;
    }

    public void invalidate()
    {

    }

    public boolean isValid()
    {
        return false;
    }

    public void putValue(String s, Object o)
    {

    }

    public Object getValue(String s)
    {
        return null;
    }

    public void removeValue(String s)
    {

    }

    public String[] getValueNames()
    {
        return new String[0];
    }

    public Certificate[] getPeerCertificates()
        throws SSLPeerUnverifiedException
    {
        return new Certificate[0];
    }

    public Certificate[] getLocalCertificates()
    {
        return new Certificate[0];
    }

    public X509Certificate[] getPeerCertificateChain()
        throws SSLPeerUnverifiedException
    {
        return new X509Certificate[0];
    }

    public Principal getPeerPrincipal()
        throws SSLPeerUnverifiedException
    {
        return null;
    }

    public Principal getLocalPrincipal()
    {
        return null;
    }

    public String getCipherSuite()
    {
        return null;
    }

    public String getProtocol()
    {
        return null;
    }

    public String getPeerHost()
    {
        return null;
    }

    public int getPeerPort()
    {
        return 0;
    }

    public int getPacketBufferSize()
    {
        return 0;
    }

    public int getApplicationBufferSize()
    {
        return 0;
    }
}
