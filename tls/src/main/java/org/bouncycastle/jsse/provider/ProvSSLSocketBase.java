package org.bouncycastle.jsse.provider;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.channels.SocketChannel;
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

    @Override
    public SocketChannel getChannel()
    {
//        return super.getChannel();
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean getOOBInline() throws SocketException
    {
        return false;
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
    public void sendUrgentData(int data) throws IOException
    {
        throw new UnsupportedOperationException("Urgent data not supported in TLS");
    }

    @Override
    public void setOOBInline(boolean on) throws SocketException
    {
        if (on)
        {
            throw new UnsupportedOperationException("Urgent data not supported in TLS");
        }
    }
    
    @Override
    public void shutdownInput() throws IOException
    {
        throw new UnsupportedOperationException("shutdownInput() not supported in TLS");
    }

    @Override
    public void shutdownOutput() throws IOException
    {
        throw new UnsupportedOperationException("shutdownOutput() not supported in TLS");
    }

    // TODO[jsse] Proper toString for sockets
//    @Override
//    public String toString()
//    {
//        return super.toString();
//    }

    protected void implBind(InetAddress clientAddress, int clientPort) throws IOException
    {
        InetSocketAddress socketAddress = new InetSocketAddress(clientAddress, clientPort);

        bind(socketAddress);
    }

    protected void implConnect(InetAddress address, int port) throws IOException
    {
        SocketAddress socketAddress = new InetSocketAddress(address, port);

        connect(socketAddress, 0);
    }

    protected void implConnect(String host, int port) throws IOException, UnknownHostException
    {
        SocketAddress socketAddress =
                null == host
            ?   new InetSocketAddress(InetAddress.getByName(null), port)
            :   new InetSocketAddress(host, port);

        connect(socketAddress, 0);
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
