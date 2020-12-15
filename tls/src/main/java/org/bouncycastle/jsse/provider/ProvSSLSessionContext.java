package org.bouncycastle.jsse.provider;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

import org.bouncycastle.tls.SessionID;
import org.bouncycastle.tls.TlsSession;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;

class ProvSSLSessionContext
    implements SSLSessionContext
{
    private static final Logger LOG = Logger.getLogger(ProvSSLSessionContext.class.getName());

    private static final int provSessionCacheSize = PropertyUtils
        .getIntegerSystemProperty("javax.net.ssl.sessionCacheSize", 20480, 0, Integer.MAX_VALUE);

    // NOTE: This is configured as a simple LRU cache using the "access order" constructor
    @SuppressWarnings("serial")
    protected final Map<SessionID, SessionEntry> sessionsByID = new LinkedHashMap<SessionID, SessionEntry>(16, 0.75f, true)
    {
        protected boolean removeEldestEntry(Map.Entry<SessionID, SessionEntry> eldest)
        {
            boolean shouldRemove = sessionCacheSize > 0 && size() > sessionCacheSize;
            if (shouldRemove)
            {
                removeSessionByPeer(eldest.getValue());
            }
            return shouldRemove;
        }
    };
    protected final Map<String, SessionEntry> sessionsByPeer = new HashMap<String, SessionEntry>();
    protected final ReferenceQueue<ProvSSLSession> sessionsQueue = new ReferenceQueue<ProvSSLSession>();

    protected final ContextData contextData;

    protected int sessionCacheSize = provSessionCacheSize;
    protected int sessionTimeoutSeconds = 86400; // 24hrs (in seconds)

    ProvSSLSessionContext(ContextData contextData)
    {
        this.contextData = contextData;
    }

    ProvSSLContextSpi getSSLContext()
    {
        return contextData.getContext();
    }

    JcaTlsCrypto getCrypto()
    {
        return contextData.getCrypto();
    }

    synchronized ProvSSLSession getSessionImpl(byte[] sessionID)
    {
        processQueue();

        return accessSession(mapGet(sessionsByID, makeSessionID(sessionID)));
    }

    synchronized ProvSSLSession getSessionImpl(String hostName, int port)
    {
        processQueue();

        SessionEntry sessionEntry = mapGet(sessionsByPeer, makePeerKey(hostName, port));
        ProvSSLSession session = accessSession(sessionEntry);
        if (session != null)
        {
            // NOTE: For the current simple cache implementation, need to 'access' the sessionByIDs entry
            sessionsByID.get(sessionEntry.getSessionID());
        }
        return session;
    }

    synchronized void removeSession(byte[] sessionID)
    {
        SessionEntry sessionEntry = mapRemove(sessionsByID, makeSessionID(sessionID));
        if (null != sessionEntry)
        {
            removeSessionByPeer(sessionEntry);
        }
    }

    synchronized ProvSSLSession reportSession(String peerHost, int peerPort, TlsSession tlsSession,
        JsseSessionParameters jsseSessionParameters, boolean addToCache)
    {
        processQueue();

        if (!addToCache)
        {
            return new ProvSSLSession(this, peerHost, peerPort, tlsSession, jsseSessionParameters);
        }

        SessionID sessionID = makeSessionID(tlsSession.getSessionID());
        SessionEntry sessionEntry = mapGet(sessionsByID, sessionID);

        ProvSSLSession session = sessionEntry == null ? null : sessionEntry.get();
        if (null == session || session.getTlsSession() != tlsSession)
        {
            session = new ProvSSLSession(this, peerHost, peerPort, tlsSession, jsseSessionParameters);

            if (null != sessionID)
            {
                sessionEntry = new SessionEntry(sessionID, session, sessionsQueue);
                sessionsByID.put(sessionID, sessionEntry);
            }
        }

        if (null != sessionEntry)
        {
            mapAdd(sessionsByPeer, sessionEntry.getPeerKey(), sessionEntry);
        }

        return session;
    }

    public synchronized Enumeration<byte[]> getIds()
    {
        removeAllExpiredSessions();

        ArrayList<byte[]> ids = new ArrayList<byte[]>(sessionsByID.size());
        for (SessionID sessionID : sessionsByID.keySet())
        {
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

        removeAllExpiredSessions();

        // Immediately remove LRU sessions in excess of the new limit
        if (sessionCacheSize > 0)
        {
            int currentSize = sessionsByID.size();
            if (currentSize > sessionCacheSize)
            {
                Iterator<SessionEntry> iter = sessionsByID.values().iterator();
                while (iter.hasNext() && currentSize > sessionCacheSize)
                {
                    SessionEntry sessionEntry = iter.next();
                    iter.remove();
                    removeSessionByPeer(sessionEntry);
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

    private ProvSSLSession accessSession(SessionEntry sessionEntry)
    {
        if (sessionEntry != null)
        {
            ProvSSLSession session = sessionEntry.get();
            if (session != null)
            {
                long currentTimeMillis = System.currentTimeMillis();
                if (!invalidateIfCreatedBefore(sessionEntry, getCreationTimeLimit(currentTimeMillis)))
                {
                    session.accessedAt(currentTimeMillis);
                    return session;
                }
            }

            removeSession(sessionEntry);
        }
        return null;
    }

    private long getCreationTimeLimit(long expiryTimeMillis)
    {
        return sessionTimeoutSeconds < 1 ? Long.MIN_VALUE : (expiryTimeMillis - 1000L * sessionTimeoutSeconds);
    }

    private boolean invalidateIfCreatedBefore(SessionEntry sessionEntry, long creationTimeLimit)
    {
        ProvSSLSession session = sessionEntry.get();
        if (session == null)
        {
            return true;
        }
        if (session.getCreationTime() < creationTimeLimit)
        {
            session.invalidate();
        }
        return !session.isValid();
    }

    private void processQueue()
    {
        int count = 0;

        SessionEntry sessionEntry;
        while ((sessionEntry = (SessionEntry)sessionsQueue.poll()) != null)
        {
            removeSession(sessionEntry);
            ++count;
        }

        if (count > 0)
        {
            LOG.fine("Processed " + count + " session entries (soft references) from the reference queue");
        }
    }

    private void removeAllExpiredSessions()
    {
        processQueue();

        long creationTimeLimit = getCreationTimeLimit(System.currentTimeMillis());

        Iterator<SessionEntry> iter = sessionsByID.values().iterator();
        while (iter.hasNext())
        {
            SessionEntry sessionEntry = iter.next();
            if (invalidateIfCreatedBefore(sessionEntry, creationTimeLimit))
            {
                iter.remove();
                removeSessionByPeer(sessionEntry);
            }
        }
    }

    private void removeSession(SessionEntry sessionEntry)
    {
        mapRemove(sessionsByID, sessionEntry.getSessionID(), sessionEntry);

        removeSessionByPeer(sessionEntry);
    }

    private boolean removeSessionByPeer(SessionEntry sessionEntry)
    {
        return mapRemove(sessionsByPeer, sessionEntry.getPeerKey(), sessionEntry);
    }

    private static String makePeerKey(ProvSSLSession session)
    {
        return session == null ? null : makePeerKey(session.getPeerHost(), session.getPeerPort());
    }

    private static String makePeerKey(String hostName, int port)
    {
        return (hostName == null || port < 0) ? null : (hostName + ':' + Integer.toString(port)).toLowerCase(Locale.ENGLISH);
    }

    private static SessionID makeSessionID(byte[] sessionID)
    {
        return (sessionID == null || sessionID.length < 1) ? null : new SessionID(sessionID);
    }

    private static <K, V> void mapAdd(Map<K, V> map, K key, V value)
    {
        if (map == null || value == null)
        {
            throw new NullPointerException();
        }
        if (key != null)
        {
            map.put(key, value);
        }
    }

    private static <K, V> V mapGet(Map<K, V> map, K key)
    {
        if (map == null)
        {
            throw new NullPointerException();
        }
        return key == null ? null : map.get(key);
    }

    private static <K, V> V mapRemove(Map<K, V> map, K key)
    {
        if (map == null)
        {
            throw new NullPointerException();
        }
        return key == null ? null : map.remove(key);
    }

    private static <K, V> boolean mapRemove(Map<K, V> map, K key, V value)
    {
        if (map == null || value == null)
        {
            throw new NullPointerException();
        }
        if (key != null)
        {
            // TODO[jsse] From 1.8 there is a 2-argument remove method to accomplish this 
            V removed = map.remove(key);
            if (removed == value)
            {
                return true;
            }
            if (removed != null)
            {
                map.put(key, removed);
            }
        }
        return false;
    }

    private static final class SessionEntry
        extends SoftReference<ProvSSLSession>
    {
        private final SessionID sessionID;
        private final String peerKey;

        SessionEntry(SessionID sessionID, ProvSSLSession session, ReferenceQueue<ProvSSLSession> queue)
        {
            super(session, queue);

            if (sessionID == null || session == null || queue == null)
            {
                throw new NullPointerException();
            }

            this.sessionID = sessionID;
            this.peerKey = makePeerKey(session);
        }

        public String getPeerKey()
        {
            return peerKey;
        }

        public SessionID getSessionID()
        {
            return sessionID;
        }
    }
}
