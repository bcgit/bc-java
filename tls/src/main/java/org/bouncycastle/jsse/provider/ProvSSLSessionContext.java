package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

import org.bouncycastle.tls.SessionID;
import org.bouncycastle.tls.TlsSession;

/*
 * TODO[jsse]
 * - Need to add sessions to the context at handshake completion
 * - Implement the cache/timeout mechanisms
 */
class ProvSSLSessionContext
    implements SSLSessionContext
{
    static final boolean hasExtendedSSLSession;

    static
    {
        Class clazz = null;
        try
        {
            clazz = ProvSSLServerSocket.class.getClassLoader().loadClass("javax.net.ssl.ExtendedSSLSession");
        }
        catch (Exception e)
        {
            clazz = null;
        }

        hasExtendedSSLSession = (clazz != null);
    }

    protected final Map<SessionID, ProvSSLSession> sessionMap = Collections.synchronizedMap(new HashMap<SessionID, ProvSSLSession>());

    protected final ProvSSLContextSpi sslContext;
    protected int sessionCacheSize = 0;
    protected int sessionTimeout = 0;

    ProvSSLSessionContext(ProvSSLContextSpi sslContext)
    {
        this.sslContext = sslContext;
    }

    ProvSSLContextSpi getSSLContext()
    {
        return sslContext;
    }

    SSLSession reportSession(TlsSession tlsSession)
    {
        // TODO[jsse] Check for existing session with same ID

        ProvSSLSession sslSession = new ProvSSLSession(this, tlsSession);

        // TODO[jsse] Register session for re-use

        if (hasExtendedSSLSession)
        {
             return new ProvExtendedSSLSession(sslSession);
        }

        return sslSession;
    }

    public Enumeration<byte[]> getIds()
    {
        synchronized (sessionMap)
        {
            Collection<SessionID> keys = sessionMap.keySet();
            ArrayList<byte[]> ids = new ArrayList<byte[]>(keys.size());
            for (SessionID key : keys)
            {
                // TODO[jsse] Filter out invalidated/timed-out sessions?
                ids.add(key.getBytes());
            }
            return Collections.enumeration(ids);
        }
    }

    public SSLSession getSession(byte[] sessionId)
    {
        SessionID key = new SessionID(sessionId);
        ProvSSLSession session = sessionMap.get(key);

        // TODO[jsse] Should we return a session if it's been invalidated/timed-out?

        return session;
    }

    public synchronized int getSessionCacheSize()
    {
        return sessionCacheSize;
    }

    public synchronized int getSessionTimeout()
    {
        return sessionTimeout;
    }

    public synchronized void setSessionCacheSize(int size) throws IllegalArgumentException
    {
        if (size < 0)
        {
            throw new IllegalArgumentException("'size' cannot be < 0");
        }

        this.sessionCacheSize = size;

        // TODO[jsse] Immediately discard any extra sessions
    }

    public synchronized void setSessionTimeout(int seconds) throws IllegalArgumentException
    {
        if (seconds < 0)
        {
            throw new IllegalArgumentException("'seconds' cannot be < 0");
        }

        this.sessionTimeout = seconds;

        // TODO[jsse] Immediately check the new timeout for all sessions
    }
}
