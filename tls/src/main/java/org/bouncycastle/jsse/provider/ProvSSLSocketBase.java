package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.channels.SocketChannel;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jsse.BCSSLSocket;

abstract class ProvSSLSocketBase
    extends SSLSocket
    implements BCSSLSocket
{
    protected final Set<HandshakeCompletedListenerAdapter> listeners = Collections.synchronizedSet(
        new HashSet<HandshakeCompletedListenerAdapter>());

    protected ProvSSLSocketBase()
    {
        super();
    }

    protected ProvSSLSocketBase(InetAddress address, int port, InetAddress clientAddress, int clientPort)
        throws IOException
    {
        super(address, port, clientAddress, clientPort);
    }

    protected ProvSSLSocketBase(InetAddress address, int port) throws IOException
    {
        super(address, port);
    }

    protected ProvSSLSocketBase(String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        super(host, port, clientAddress, clientPort);
    }

    protected ProvSSLSocketBase(String host, int port) throws IOException, UnknownHostException
    {
        super(host, port);
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener)
    {
        if (listener == null)
        {
            throw new IllegalArgumentException("'listener' cannot be null");
        }

        listeners.add(new HandshakeCompletedListenerAdapter(listener));
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
        if (!listeners.remove(new HandshakeCompletedListenerAdapter(listener)))
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
}
