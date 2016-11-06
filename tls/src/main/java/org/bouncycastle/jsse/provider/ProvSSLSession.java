package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;

// TODO[jsse] Serializable ?
class ProvSSLSession
    extends ExtendedSSLSession
{
    // TODO[jsse] Ensure this behaves according to the javadoc for SSLSocket.getSession and SSLEngine.getSession
    protected final static ProvSSLSession NULL_SESSION = new ProvSSLSession(null);

    protected final Map<String, Object> valueMap = Collections.synchronizedMap(new HashMap<String, Object>());

    protected final ProvSSLSessionContext context;

    ProvSSLSession(ProvSSLSessionContext context)
    {
        this.context = context;
    }
    
    public int getApplicationBufferSize()
    {
        throw new UnsupportedOperationException();
    }

    public String getCipherSuite()
    {
        throw new UnsupportedOperationException();
    }

    public long getCreationTime()
    {
        throw new UnsupportedOperationException();
    }

    public byte[] getId()
    {
        throw new UnsupportedOperationException();
    }

    public long getLastAccessedTime()
    {
        throw new UnsupportedOperationException();
    }

    public Certificate[] getLocalCertificates()
    {
        throw new UnsupportedOperationException();
    }

    public Principal getLocalPrincipal()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getLocalSupportedSignatureAlgorithms()
    {
        throw new UnsupportedOperationException();
    }

    public int getPacketBufferSize()
    {
        throw new UnsupportedOperationException();
    }

    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException
    {
        throw new UnsupportedOperationException();
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException
    {
        throw new UnsupportedOperationException();
    }

    public String getPeerHost()
    {
        throw new UnsupportedOperationException();
    }

    public int getPeerPort()
    {
        throw new UnsupportedOperationException();
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getPeerSupportedSignatureAlgorithms()
    {
        throw new UnsupportedOperationException();
    }

    public String getProtocol()
    {
        throw new UnsupportedOperationException();
    }

//    @Override
//    public List<SNIServerName> getRequestedServerNames()
//    {
//        return super.getRequestedServerNames();
//    }

    public SSLSessionContext getSessionContext()
    {
        return context;
    }

    public Object getValue(String name)
    {
        return valueMap.get(name);
    }

    public String[] getValueNames()
    {
        synchronized (valueMap)
        {
            return valueMap.keySet().toArray(new String[valueMap.size()]);
        }
    }

    public void invalidate()
    {
        throw new UnsupportedOperationException();
    }

    public boolean isValid()
    {
        throw new UnsupportedOperationException();
    }

    public void putValue(String name, Object value)
    {
        notifyUnbound(name, valueMap.put(name, value));
        notifyBound(name, value);
    }

    public void removeValue(String name)
    {
        notifyUnbound(name, valueMap.remove(name));
    }

    protected void notifyBound(String name, Object value)
    {
        if (value instanceof SSLSessionBindingListener)
        {
            new SessionBindingListenerAdapter((SSLSessionBindingListener)value)
                .valueBound(new SSLSessionBindingEvent(this, name));
        }
    }

    protected void notifyUnbound(String name, Object value)
    {
        if (value instanceof SSLSessionBindingListener)
        {
            new SessionBindingListenerAdapter((SSLSessionBindingListener)value)
                .valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }
}
