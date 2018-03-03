package org.bouncycastle.jsse.provider;

import java.lang.reflect.Constructor;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.RecordFormat;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

// TODO[jsse] Serializable ?
class ProvSSLSessionImpl
    implements ProvSSLSession
{
    static final Constructor<? extends SSLSession> extendedSessionConstructor;

    static
    {
        Constructor<? extends SSLSession> cons = null;
        try
        {
            if (null != JsseUtils.loadClass(ProvSSLSessionImpl.class, "javax.net.ssl.ExtendedSSLSession"))
            {
                String className;
                if (null != JsseUtils.loadClass(ProvSSLSessionImpl.class, "javax.net.ssl.SNIHostName"))
                {
                    className = "org.bouncycastle.jsse.provider.ProvExtendedSSLSession_8";
                }
                else
                {
                    className = "org.bouncycastle.jsse.provider.ProvExtendedSSLSession_7";
                }

                Class<? extends SSLSession> clazz = JsseUtils.loadClass(ProvSSLSessionContext.class, className);

                cons = JsseUtils.getDeclaredConstructor(clazz, ProvSSLSession.class);
            }
        }
        catch (Exception e)
        {
        }

        extendedSessionConstructor = cons;
    }

    static SSLSession makeExportSession(ProvSSLSession sslSession)
    {
        if (extendedSessionConstructor != null)
        {
            try
            {
                return extendedSessionConstructor.newInstance(sslSession);
            }
            catch (Exception e)
            {
            }
        }

        return sslSession;
    }

    // TODO[jsse] Ensure this behaves according to the javadoc for SSLSocket.getSession and SSLEngine.getSession
    protected final static ProvSSLSessionImpl NULL_SESSION = new ProvSSLSessionImpl(null, null, null, -1);

    protected final Map<String, Object> valueMap = Collections.synchronizedMap(new HashMap<String, Object>());

    protected final ProvSSLSessionContext sslSessionContext;
    protected final TlsSession tlsSession;
    protected final String peerHost;
    protected final int peerPort;
    protected final SessionParameters sessionParameters;
    protected final SSLSession exportSession;
    protected final long creationTime;

    protected long lastAccessedTime;

    ProvSSLSessionImpl(ProvSSLSessionContext sslSessionContext, TlsSession tlsSession, String peerHost, int peerPort)
    {
        this.sslSessionContext = sslSessionContext;
        this.tlsSession = tlsSession;
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.sessionParameters = tlsSession == null ? null : tlsSession.exportSessionParameters();
        this.exportSession = makeExportSession(this);
        this.creationTime = System.currentTimeMillis();
        this.lastAccessedTime = creationTime;
    }

    SSLSession getExportSession()
    {
        return exportSession;
    }

    TlsSession getTlsSession()
    {
        return tlsSession;
    }

    synchronized void accessedAt(long accessTime)
    {
        this.lastAccessedTime = Math.max(lastAccessedTime, accessTime);
    }

    public int getApplicationBufferSize()
    {
        // TODO[jsse] See comments for getPacketBufferSize
        return 1 << 14; 
    }

    public String getCipherSuite()
    {
        return sessionParameters == null
            ?   null
            :   sslSessionContext.getSSLContext().getCipherSuiteString(sessionParameters.getCipherSuite());
    }

    public long getCreationTime()
    {
        return creationTime;
    }

    public byte[] getId()
    {
        byte[] id = tlsSession == null
            ?   null
            :   Arrays.clone(tlsSession.getSessionID());
        return id == null ? TlsUtils.EMPTY_BYTES : id;
    }

    public long getLastAccessedTime()
    {
        return lastAccessedTime;
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

    public String[] getLocalSupportedSignatureAlgorithms()
    {
        throw new UnsupportedOperationException();
    }

    public int getPacketBufferSize()
    {
        /*
         * TODO[jsse] This is the maximum possible per RFC (but see jsse.SSLEngine.acceptLargeFragments System property).
         * It would be nice to dynamically check with the underlying RecordStream, which might know a tighter limit, e.g.
         * when the max_fragment_length extension has been negotiated, or when no compression was negotiated).
         */
        // Header size + Fragment length limit + Compression expansion + Cipher expansion
//        return RecordFormat.FRAGMENT_OFFSET + (1 << 14) + 1024 + 1024;

        /*
         * Worst case accounts for possible application data splitting (before TLS 1.1)
         */
        return (1 << 14) + 1 + 2 * (RecordFormat.FRAGMENT_OFFSET + 1024 + 1024);
    }

    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException
    {
        /*
         * "Note: this method exists for compatibility with previous releases. New applications
         * should use getPeerCertificates() instead."
         */
        Certificate[] peerCertificates = getPeerCertificates();
        try
        {
            javax.security.cert.X509Certificate[] chain = new javax.security.cert.X509Certificate[peerCertificates.length];
            for (int i = 0; i < peerCertificates.length; ++i)
            {
                chain[i] = javax.security.cert.X509Certificate.getInstance(peerCertificates[i].getEncoded());
            }
            return chain;
        }
        catch (Exception e)
        {
            throw new SSLPeerUnverifiedException(e.getMessage());
        }
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

    public String getPeerHost()
    {
        return peerHost;
    }

    public int getPeerPort()
    {
        return peerPort;
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

    public String[] getPeerSupportedSignatureAlgorithms()
    {
        throw new UnsupportedOperationException();
    }

    public String getProtocol()
    {
        return sessionParameters == null
            ?   null
            :   sslSessionContext.getSSLContext().getProtocolString(sessionParameters.getNegotiatedVersion());
    }

    public List<BCSNIServerName> getRequestedServerNames()
    {
        throw new UnsupportedOperationException();
    }

    public SSLSessionContext getSessionContext()
    {
        return sslSessionContext;
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
        if (tlsSession != null)
        {
            tlsSession.invalidate();
        }
    }

    public boolean isValid()
    {
        return tlsSession != null && tlsSession.isResumable();
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
