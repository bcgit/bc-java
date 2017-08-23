package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;

import org.bouncycastle.jsse.BCSNIServerName;

// TODO[jsse] Serializable ?
class ProvExtendedSSLSession
    extends ExtendedSSLSession
{
    private final ProvSSLSession sslSession;

    ProvExtendedSSLSession(ProvSSLSession sslSession)
    {
        this.sslSession = sslSession;
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
        return sslSession.getLocalSupportedSignatureAlgorithms();
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
        return sslSession.getPeerSupportedSignatureAlgorithms();
    }

    public String getProtocol()
    {
        return sslSession.getProtocol();
    }

    public List<SNIServerName> getRequestedServerNames()
    {
        List<BCSNIServerName> serverNames = sslSession.getRequestedServerNames();
        if (serverNames != null)
        {
            ArrayList<SNIServerName> result = new ArrayList<SNIServerName>(serverNames.size());
            for (BCSNIServerName serverName : serverNames)
            {
                SNIServerName exported = JsseUtilsv18.exportSNIServerName(serverName);
                if (exported != null)
                {
                    result.add(exported);
                }
            }
            if (!result.isEmpty())
            {
                return Collections.unmodifiableList(result);
            }
        }
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
