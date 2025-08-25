package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLPermission;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionBindingEvent;
import javax.net.ssl.SSLSessionBindingListener;
import javax.net.ssl.SSLSessionContext;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jsse.BCExtendedSSLSession;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.RecordFormat;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.util.Arrays;

abstract class ProvSSLSessionBase
    extends BCExtendedSSLSession
{
    protected final AtomicReference<ProvSSLSessionContext> sslSessionContext;
    protected final ConcurrentHashMap<String, Object> valueMap;
    protected final boolean fipsMode;
    protected final JcaTlsCrypto crypto;
    protected final String peerHost;
    protected final int peerPort;
    protected final long creationTime;
    protected final SSLSession exportSSLSession;

    ProvSSLSessionBase(ProvSSLSessionContext sslSessionContext, ConcurrentHashMap<String, Object> valueMap,
        String peerHost, int peerPort, long creationTime)
    {
        this.sslSessionContext = new AtomicReference<ProvSSLSessionContext>(sslSessionContext);
        this.valueMap = valueMap;
        this.fipsMode = (null == sslSessionContext) ? false : sslSessionContext.getContextData().isFipsMode();
        this.crypto = (null == sslSessionContext) ? null : sslSessionContext.getContextData().getCrypto();
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.creationTime = creationTime;
        this.exportSSLSession = SSLSessionUtil.exportSSLSession(this);
    }

    protected abstract int getCipherSuiteTLS();

    protected abstract byte[] getIDArray();

    protected abstract JsseSecurityParameters getJsseSecurityParameters();

    protected abstract JsseSessionParameters getJsseSessionParameters();

    protected abstract org.bouncycastle.tls.Certificate getLocalCertificateTLS();

    protected abstract org.bouncycastle.tls.Certificate getPeerCertificateTLS();

    protected abstract ProtocolVersion getProtocolTLS();

    protected abstract void invalidateTLS();

    SSLSession getExportSSLSession()
    {
        return exportSSLSession;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof ProvSSLSessionBase))
        {
            return false;
        }

        ProvSSLSessionBase other = (ProvSSLSessionBase)obj;
        return Arrays.areEqual(getIDArray(), other.getIDArray());
    }

    public int getApplicationBufferSize()
    {
        // TODO[jsse] See comments for getPacketBufferSize
        return 1 << 14; 
    }

    public String getCipherSuite()
    {
        return ProvSSLContextSpi.getCipherSuiteName(getCipherSuiteTLS());
    }

    public long getCreationTime()
    {
        return creationTime;
    }

    public byte[] getId()
    {
        byte[] id = getIDArray();
        return TlsUtils.isNullOrEmpty(id) ? TlsUtils.EMPTY_BYTES : id.clone();
    }

    public Certificate[] getLocalCertificates()
    {
        if (null != crypto)
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(crypto, getLocalCertificateTLS());
            if (null != chain && chain.length > 0)
            {
                return chain;
            }
        }

        return null;
    }

    public Principal getLocalPrincipal()
    {
        if (null != crypto)
        {
            return JsseUtils.getSubject(crypto, getLocalCertificateTLS());
        }

        return null;
    }

    public int getPacketBufferSize()
    {
        /*
         * TODO[jsse] This is the maximum possible per RFC (but see jsse.SSLEngine.acceptLargeFragments System property).
         * It would be nice to dynamically check with the underlying RecordStream, which might know a tighter limit, e.g.
         * when the max_fragment_length extension has been negotiated. (Compression is not supported, so no expansion needed).
         */

        ProtocolVersion protocolVersion = getProtocolTLS();
        if (null == protocolVersion || !TlsUtils.isTLSv11(protocolVersion))
        {
            // Worst case accounts for possible application data splitting (before TLS 1.1)
            return (1 << 14) + 1 + (RecordFormat.FRAGMENT_OFFSET + 1024) * 2;
        }

        if (TlsUtils.isTLSv13(protocolVersion))
        {
            // Worst case accounts for possible key_update message (from TLS 1.3)
            return (1 << 14) + 5 + (RecordFormat.FRAGMENT_OFFSET + 256) * 2;
        }

        return (1 << 14) + (RecordFormat.FRAGMENT_OFFSET + 1024);
    }

    @SuppressWarnings("deprecation")
    public javax.security.cert.X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException
    {
        /*
         * "Note: this method exists for compatibility with previous releases. New applications
         * should use getPeerCertificates() instead."
         */
        return OldCertUtil.getPeerCertificateChain(this);
    }

    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException
    {
        if (null != crypto)
        {
            X509Certificate[] chain = JsseUtils.getX509CertificateChain(crypto, getPeerCertificateTLS());
            if (null != chain && chain.length > 0)
            {
                return chain;
            }
        }

        throw new SSLPeerUnverifiedException("No peer identity established");
    }

    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException
    {
        if (null != crypto)
        {
            X500Principal principal = JsseUtils.getSubject(crypto, getPeerCertificateTLS());
            if (null != principal)
            {
                return principal;
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

    public String getProtocol()
    {
        return ProvSSLContextSpi.getProtocolVersionName(getProtocolTLS());
    }

    public SSLSessionContext getSessionContext()
    {
        SecurityManager sm = System.getSecurityManager();
        if (null != sm)
        {
            sm.checkPermission(new SSLPermission("getSSLSessionContext"));
        }

        return sslSessionContext.get();
    }

    public Object getValue(String name)
    {
        if (name == null)
        {
            throw new IllegalArgumentException("'name' cannot be null");
        }

        return valueMap.get(name);
    }

    ConcurrentHashMap<String, Object> getValueMap()
    {
        return valueMap;
    }

    public String[] getValueNames()
    {
        return valueMap.keySet().toArray(new String[0]);
    }

    @Override
    public int hashCode()
    {
        return Arrays.hashCode(getIDArray());
    }

    public final void invalidate()
    {
        implInvalidate(true);
    }

    final void invalidatedBySessionContext()
    {
        implInvalidate(false);
    }

    public boolean isFipsMode()
    {
        return fipsMode;
    }

    public boolean isValid()
    {
        if (null == sslSessionContext.get())
        {
            return false;
        }

        // TODO[tls13] Resumption/PSK. TLS 1.3 doesn't need a session ID for resumption?
//        if (ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(getProtocolTLS()))
//        {
//            return true;
//        }

        return !TlsUtils.isNullOrEmpty(getIDArray());
    }

    public void putValue(String name, Object value)
    {
        if (name == null)
        {
            throw new IllegalArgumentException("'name' cannot be null");
        }
        if (value == null)
        {
            throw new IllegalArgumentException("'value' cannot be null");
        }

        notifyUnbound(name, valueMap.put(name, value));
        notifyBound(name, value);
    }

    public void removeValue(String name)
    {
        if (name == null)
        {
            throw new IllegalArgumentException("'name' cannot be null");
        }

        notifyUnbound(name, valueMap.remove(name));
    }

    @Override
    public String toString()
    {
        return "Session(" + getCreationTime() + "|" + getCipherSuite() + ")";
    }

    protected void notifyBound(String name, Object value)
    {
        if (value instanceof SSLSessionBindingListener)
        {
            ((SSLSessionBindingListener)value).valueBound(new SSLSessionBindingEvent(this, name));
        }
    }

    protected void notifyUnbound(String name, Object value)
    {
        if (value instanceof SSLSessionBindingListener)
        {
            ((SSLSessionBindingListener)value).valueUnbound(new SSLSessionBindingEvent(this, name));
        }
    }

    private void implInvalidate(boolean removeFromSessionContext)
    {
        // NOTE: The NULL_SESSION never actually gets invalidated (consistent with SunJSSE)

        if (removeFromSessionContext)
        {
            ProvSSLSessionContext context = sslSessionContext.getAndSet(null);
            if (null != context)
            {
                context.removeSession(getIDArray());
            }
        }
        else
        {
            sslSessionContext.set(null);
        }

        invalidateTLS();
    }

    protected static ConcurrentHashMap<String, Object> createValueMap()
    {
        return new ConcurrentHashMap<String, Object>();
    }

    protected static long getCurrentTime()
    {
        return System.currentTimeMillis();
    }
}
