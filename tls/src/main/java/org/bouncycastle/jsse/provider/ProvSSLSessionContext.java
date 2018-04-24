package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

import org.bouncycastle.tls.SessionID;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.crypto.TlsCrypto;

class ProvSSLSessionContext
    implements SSLSessionContext
{
    private static final int provSessionCacheSize = PropertyUtils
        .getIntegerSystemProperty("javax.net.ssl.sessionCacheSize", 0, 0, Integer.MAX_VALUE);

    // NOTE: This is configured as a simple LRU cache using the "access order" constructor
    protected final Map<SessionID, ProvSSLSessionImpl> sessionsByID = new LinkedHashMap<SessionID, ProvSSLSessionImpl>(16, 0.75f, true)
    {
        protected boolean removeEldestEntry(Map.Entry<SessionID, ProvSSLSessionImpl> eldest)
        {
            boolean shouldRemove = sessionCacheSize > 0 && size() > sessionCacheSize;
            if (shouldRemove)
            {
                removeSessionByPeer(eldest.getValue());
            }
            return shouldRemove;
        }
    };
    protected final Map<String, ProvSSLSessionImpl> sessionsByPeer = new HashMap<String, ProvSSLSessionImpl>();

    protected final ProvSSLContextSpi sslContext;
    protected final TlsCrypto crypto;

    protected int sessionCacheSize = provSessionCacheSize;
    protected int sessionTimeoutSeconds = 86400; // 24hrs (in seconds)

    ProvSSLSessionContext(ProvSSLContextSpi sslContext, TlsCrypto crypto)
    {
        this.sslContext = sslContext;
        this.crypto = crypto;
    }

    ProvSSLContextSpi getSSLContext()
    {
        return sslContext;
    }

    TlsCrypto getCrypto()
    {
        return crypto;
    }

    synchronized ProvSSLSessionImpl getSessionImpl(byte[] sessionID)
    {
        if (sessionID == null || sessionID.length < 1)
        {
            return null;
        }

        return checkSession(sessionsByID.get(new SessionID(sessionID)));
    }

    synchronized ProvSSLSessionImpl getSessionImpl(String hostName, int port)
    {
        if (hostName == null || port < 0)
        {
            return null;
        }

        ProvSSLSessionImpl sslSession = checkSession(sessionsByPeer.get(makePeerKey(hostName, port)));
        if (sslSession != null)
        {
            // NOTE: For the current simple cache implementation, need to 'access' the sessionByIDs entry
            sessionsByID.get(new SessionID(sslSession.getId()));
        }
        return sslSession;
    }

    synchronized ProvSSLSessionImpl reportSession(TlsSession tlsSession, String peerHost, int peerPort)
    {
        SessionID sessionID = new SessionID(tlsSession.getSessionID());

        ProvSSLSessionImpl sslSession = sessionsByID.get(sessionID);
        if (sslSession == null || sslSession.getTlsSession() != tlsSession)
        {
            sslSession = new ProvSSLSessionImpl(this, tlsSession, peerHost, peerPort);
            sessionsByID.put(sessionID, sslSession);
        }

        addSessionByPeer(sslSession);

        return sslSession;
    }

    public synchronized Enumeration<byte[]> getIds()
    {
        removeAllExpiredSessions();

        ArrayList<byte[]> ids = new ArrayList<byte[]>(sessionsByID.size());

        Iterator<SessionID> iter = sessionsByID.keySet().iterator();
        while (iter.hasNext())
        {
            SessionID sessionID = iter.next();
            ids.add(sessionID.getBytes());
        }

        return Collections.enumeration(ids);
    }

    public SSLSession getSession(byte[] sessionID)
    {
        if (sessionID == null)
        {
            throw new NullPointerException("'sessionID' cannot be null");
        }

        return getSessionImpl(sessionID);
    }

    public synchronized int getSessionCacheSize()
    {
        return sessionCacheSize;
    }

    public synchronized int getSessionTimeout()
    {
        return sessionTimeoutSeconds;
    }

    public synchronized void setSessionCacheSize(int size) throws IllegalArgumentException
    {
        if (sessionCacheSize == size)
        {
            return;
        }

        if (size < 0)
        {
            throw new IllegalArgumentException("'size' cannot be < 0");
        }

        this.sessionCacheSize = size;

        // Immediately remove LRU sessions in excess of the new limit
        if (sessionCacheSize > 0)
        {
            int currentSize = sessionsByID.size();
            if (currentSize > sessionCacheSize)
            {
                Iterator<ProvSSLSessionImpl> iter = sessionsByID.values().iterator();
                while (iter.hasNext() && currentSize > sessionCacheSize)
                {
                    ProvSSLSessionImpl sslSession = iter.next();
                    iter.remove();
                    removeSessionByPeer(sslSession);
                    --currentSize;
                }
            }
        }
    }

    public synchronized void setSessionTimeout(int seconds) throws IllegalArgumentException
    {
        if (sessionTimeoutSeconds == seconds)
        {
            return;
        }

        if (seconds < 0)
        {
            throw new IllegalArgumentException("'seconds' cannot be < 0");
        }

        this.sessionTimeoutSeconds = seconds;

        removeAllExpiredSessions();
    }

    private void addSessionByPeer(ProvSSLSessionImpl sslSession)
    {
        if (sslSession != null && sslSession.getPeerHost() != null && sslSession.getPeerPort() >= 0)
        {
            String peerKey = makePeerKey(sslSession.getPeerHost(), sslSession.getPeerPort());
            sessionsByPeer.put(peerKey, sslSession);
        }
    }

    private ProvSSLSessionImpl checkSession(ProvSSLSessionImpl sslSession)
    {
        if (sslSession != null)
        {
            long currentTimeMillis = System.currentTimeMillis();
            invalidateIfExpiredBefore(sslSession, currentTimeMillis);

            if (sslSession.isValid())
            {
                sslSession.accessedAt(currentTimeMillis);
                return sslSession;
            }

            removeSessionByID(sslSession);
            removeSessionByPeer(sslSession);
        }
        return null;
    }

    private void invalidateIfCreatedBefore(ProvSSLSessionImpl sslSession, long creationTimeLimit)
    {
        if (sslSession.getCreationTime() < creationTimeLimit)
        {
            sslSession.invalidate();
        }
    }

    private void invalidateIfExpiredBefore(ProvSSLSessionImpl sslSession, long expiryTimeMillis)
    {
        if (sessionTimeoutSeconds > 0)
        {
            long creationTimeLimit = expiryTimeMillis - 1000L * sessionTimeoutSeconds;
            invalidateIfCreatedBefore(sslSession, creationTimeLimit);
        }
    }

    private void removeAllExpiredSessions()
    {
        if (sessionTimeoutSeconds == 0)
        {
            return; 
        }

        long creationTimeLimit = System.currentTimeMillis() - 1000L * sessionTimeoutSeconds;

        Iterator<ProvSSLSessionImpl> iter = sessionsByID.values().iterator();
        while (iter.hasNext())
        {
            ProvSSLSessionImpl sslSession = iter.next();
            invalidateIfCreatedBefore(sslSession, creationTimeLimit);

            if (!sslSession.isValid())
            {
                iter.remove();
                removeSessionByPeer(sslSession);
            }
        }
    }

    private boolean removeSessionByID(ProvSSLSessionImpl sslSession)
    {
        if (sslSession != null)
        {
            byte[] sessionID = sslSession.getId();
            if (sessionID != null & sessionID.length > 0)
            {
                return null != sessionsByID.remove(new SessionID(sessionID));
            }
        }
        return false;
    }

    private boolean removeSessionByPeer(ProvSSLSessionImpl sslSession)
    {
        if (sslSession != null && sslSession.getPeerHost() != null && sslSession.getPeerPort() >= 0)
        {
            String peerKey = makePeerKey(sslSession.getPeerHost(), sslSession.getPeerPort());
            return null != sessionsByPeer.remove(peerKey);
        }
        return false;
    }

    private static String makePeerKey(String hostName, int port)
    {
        return (hostName + ':' + Integer.toString(port)).toLowerCase(Locale.ENGLISH);
    }
}
