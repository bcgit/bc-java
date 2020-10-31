package org.bouncycastle.jsse.provider;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCSSLSocket;

abstract class ProvSSLSocketBase
    extends SSLSocket
    implements BCSSLSocket
{
    protected static final boolean provJdkTlsTrustNameService = PropertyUtils
        .getBooleanSystemProperty("jdk.tls.trustNameService", false);

    protected final Closeable socketCloser = new Closeable()
    {
        public void close() throws IOException
        {
            closeSocket();
        }
    };

    protected final Map<HandshakeCompletedListener, AccessControlContext> listeners = Collections.synchronizedMap(
        new HashMap<HandshakeCompletedListener, AccessControlContext>(4));

    protected ProvSSLSocketBase()
    {
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener)
    {
        if (listener == null)
        {
            throw new IllegalArgumentException("'listener' cannot be null");
        }

        listeners.put(listener, AccessController.getContext());
    }

    protected void closeSocket() throws IOException
    {
        super.close();
    }

    public void connect(String host, int port, int timeout) throws IOException
    {
        setHost(host);

        connect(createInetSocketAddress(host, port), timeout);
    }

    @Override
    public final boolean getOOBInline() throws SocketException
    {
        throw new SocketException(
            "This method is ineffective, since sending urgent data is not supported by SSLSockets");
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener)
    {
        if (listener == null)
        {
            throw new IllegalArgumentException("'listener' cannot be null");
        }
        if (null == listeners.remove(listener))
        {
            throw new IllegalArgumentException("'listener' is not registered");
        }
    }

    @Override
    public final void sendUrgentData(int data) throws IOException
    {
        throw new SocketException("This method is not supported by SSLSockets");
    }

    @Override
    public final void setOOBInline(boolean on) throws SocketException
    {
        throw new SocketException("This method is ineffective, since sending urgent data is not supported by SSLSockets");
    }

    // TODO[jsse] Proper toString for sockets
//    @Override
//    public String toString()
//    {
//        return super.toString();
//    }

    protected InetSocketAddress createInetSocketAddress(InetAddress address, int port) throws IOException
    {
        return new InetSocketAddress(address, port);
    }

    protected InetSocketAddress createInetSocketAddress(String host, int port) throws IOException
    {
        return null == host
            ? new InetSocketAddress(InetAddress.getByName(null), port)
            : new InetSocketAddress(host, port);
    }

    protected void implBind(InetAddress clientAddress, int clientPort) throws IOException
    {
        bind(createInetSocketAddress(clientAddress, clientPort));
    }

    protected void implConnect(InetAddress address, int port) throws IOException
    {
        connect(createInetSocketAddress(address, port), 0);
    }

    protected void implConnect(String host, int port) throws IOException, UnknownHostException
    {
        connect(createInetSocketAddress(host, port), 0);
    }

    protected void notifyHandshakeCompletedListeners(final SSLSession eventSession)
    {
        final Collection<Map.Entry<HandshakeCompletedListener, AccessControlContext>> entries = getHandshakeCompletedEntries();
        if (null == entries)
        {
            return;
        }

        final HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, eventSession);

        final Runnable notifyRunnable = new Runnable()
        {
            public void run()
            {
                for (Map.Entry<HandshakeCompletedListener, AccessControlContext> entry : entries)
                {
                    final HandshakeCompletedListener listener = entry.getKey();
                    final AccessControlContext accessControlContext = entry.getValue();

                    AccessController.doPrivileged(new PrivilegedAction<Void>()
                    {
                        public Void run()
                        {
                            listener.handshakeCompleted(event);
                            return null;
                        }
                    }, accessControlContext);
                }
            }
        };

        SSLSocketUtil.handshakeCompleted(notifyRunnable);
    }

    private Collection<Map.Entry<HandshakeCompletedListener, AccessControlContext>> getHandshakeCompletedEntries()
    {
        synchronized (listeners)
        {
            return listeners.isEmpty()
                ? null
                : new ArrayList<Map.Entry<HandshakeCompletedListener, AccessControlContext>>(listeners.entrySet());
        }
    }
}
