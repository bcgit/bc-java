package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

class ProvSSLSocket extends SSLSocket
{
    protected final Set<HandshakeCompletedListenerAdapter> listeners = Collections.synchronizedSet(
        new HashSet<HandshakeCompletedListenerAdapter>());

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
    public boolean getEnableSessionCreation()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getEnabledCipherSuites()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getEnabledProtocols()
    {
        throw new UnsupportedOperationException();
    }

//    @Override
//    public SSLSession getHandshakeSession()
//    {
//        return super.getHandshakeSession();
//    }

    @Override
    public boolean getNeedClientAuth()
    {
        throw new UnsupportedOperationException();
    }

//    @Override
//    public SSLParameters getSSLParameters()
//    {
//        return super.getSSLParameters();
//    }

    @Override
    public SSLSession getSession()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getSupportedProtocols()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean getUseClientMode()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean getWantClientAuth()
    {
        throw new UnsupportedOperationException();
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
    public void setEnableSessionCreation(boolean flag)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setEnabledProtocols(String[] protocols)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setNeedClientAuth(boolean need)
    {
        throw new UnsupportedOperationException();
    }

//    @Override
//    public void setSSLParameters(SSLParameters params)
//    {
//        super.setSSLParameters(params);
//    }

    @Override
    public void setUseClientMode(boolean mode)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setWantClientAuth(boolean want)
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void startHandshake() throws IOException
    {
        throw new UnsupportedOperationException();

        // TODO[tls-ops]
//        if (!listeners.isEmpty())
//        {
//            HandshakeCompletedEvent event = new HandshakeCompletedEvent(this, getSession());
//            synchronized (listeners)
//            {
//                for (HandshakeCompletedListener listener : listeners)
//                {
//                    listener.handshakeCompleted(event);
//                }
//            }
//        }
    }

//    @Override
//    public void connect(SocketAddress endpoint) throws IOException
//    {
//        super.connect(endpoint);
//    }

//    @Override
//    public void connect(SocketAddress endpoint, int timeout) throws IOException
//    {
//        super.connect(endpoint, timeout);
//    }

//    @Override
//    public void bind(SocketAddress bindpoint) throws IOException
//    {
//        super.bind(bindpoint);
//    }

//    @Override
//    public InetAddress getInetAddress()
//    {
//        return super.getInetAddress();
//    }

//    @Override
//    public InetAddress getLocalAddress()
//    {
//        return super.getLocalAddress();
//    }

//    @Override
//    public int getPort()
//    {
//        return super.getPort();
//    }

//    @Override
//    public int getLocalPort()
//    {
//        return super.getLocalPort();
//    }

//    @Override
//    public SocketAddress getRemoteSocketAddress()
//    {
//        return super.getRemoteSocketAddress();
//    }

//    @Override
//    public SocketAddress getLocalSocketAddress()
//    {
//        return super.getLocalSocketAddress();
//    }

//    @Override
//    public SocketChannel getChannel()
//    {
//        return super.getChannel();
//    }

//    @Override
//    public InputStream getInputStream() throws IOException
//    {
//        return super.getInputStream();
//    }

//    @Override
//    public OutputStream getOutputStream() throws IOException
//    {
//        return super.getOutputStream();
//    }

//    @Override
//    public void setTcpNoDelay(boolean on) throws SocketException
//    {
//        super.setTcpNoDelay(on);
//    }

//    @Override
//    public boolean getTcpNoDelay() throws SocketException
//    {
//        return super.getTcpNoDelay();
//    }

//    @Override
//    public void setSoLinger(boolean on, int linger) throws SocketException
//    {
//        super.setSoLinger(on, linger);
//    }

//    @Override
//    public int getSoLinger() throws SocketException
//    {
//        return super.getSoLinger();
//    }

//    @Override
//    public void sendUrgentData(int data) throws IOException
//    {
//        super.sendUrgentData(data);
//    }

//    @Override
//    public void setOOBInline(boolean on) throws SocketException
//    {
//        super.setOOBInline(on);
//    }

//    @Override
//    public boolean getOOBInline() throws SocketException
//    {
//        return super.getOOBInline();
//    }

//    @Override
//    public synchronized void setSoTimeout(int timeout) throws SocketException
//    {
//        super.setSoTimeout(timeout);
//    }

//    @Override
//    public synchronized int getSoTimeout() throws SocketException
//    {
//        return super.getSoTimeout();
//    }

//    @Override
//    public synchronized void setSendBufferSize(int size) throws SocketException
//    {
//        super.setSendBufferSize(size);
//    }

//    @Override
//    public synchronized int getSendBufferSize() throws SocketException
//    {
//        return super.getSendBufferSize();
//    }

//    @Override
//    public synchronized void setReceiveBufferSize(int size) throws SocketException
//    {
//        super.setReceiveBufferSize(size);
//    }

//    @Override
//    public synchronized int getReceiveBufferSize() throws SocketException
//    {
//        return super.getReceiveBufferSize();
//    }

//    @Override
//    public void setKeepAlive(boolean on) throws SocketException
//    {
//        super.setKeepAlive(on);
//    }

//    @Override
//    public boolean getKeepAlive() throws SocketException
//    {
//        return super.getKeepAlive();
//    }

//    @Override
//    public void setTrafficClass(int tc) throws SocketException
//    {
//        super.setTrafficClass(tc);
//    }

//    @Override
//    public int getTrafficClass() throws SocketException
//    {
//        return super.getTrafficClass();
//    }

//    @Override
//    public void setReuseAddress(boolean on) throws SocketException
//    {
//        super.setReuseAddress(on);
//    }

//    @Override
//    public boolean getReuseAddress() throws SocketException
//    {
//        return super.getReuseAddress();
//    }

//    @Override
//    public synchronized void close() throws IOException
//    {
//        super.close();
//    }

//    @Override
//    public void shutdownInput() throws IOException
//    {
//        super.shutdownInput();
//    }

//    @Override
//    public void shutdownOutput() throws IOException
//    {
//        super.shutdownOutput();
//    }

//    @Override
//    public String toString()
//    {
//        return super.toString();
//    }

//    @Override
//    public boolean isConnected()
//    {
//        return super.isConnected();
//    }

//    @Override
//    public boolean isBound()
//    {
//        return super.isBound();
//    }

//    @Override
//    public boolean isClosed()
//    {
//        return super.isClosed();
//    }

//    @Override
//    public boolean isInputShutdown()
//    {
//        return super.isInputShutdown();
//    }

//    @Override
//    public boolean isOutputShutdown()
//    {
//        return super.isOutputShutdown();
//    }

//    @Override
//    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth)
//    {
//        super.setPerformancePreferences(connectionTime, latency, bandwidth);
//    }
}
