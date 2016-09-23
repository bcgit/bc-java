package org.bouncycastle.jsse.provider;

import java.io.IOException;

import javax.net.ssl.SSLServerSocket;

class ProvSSLServerSocket
    extends SSLServerSocket
{
    ProvSSLServerSocket() throws IOException
    {
        super();
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

//    @Override
//    public void bind(SocketAddress endpoint) throws IOException
//    {
//        super.bind(endpoint);
//    }

//    @Override
//    public void bind(SocketAddress endpoint, int backlog) throws IOException
//    {
//        super.bind(endpoint, backlog);
//    }

//    @Override
//    public InetAddress getInetAddress()
//    {
//        return super.getInetAddress();
//    }

//    @Override
//    public int getLocalPort()
//    {
//        return super.getLocalPort();
//    }

//    @Override
//    public SocketAddress getLocalSocketAddress()
//    {
//        return super.getLocalSocketAddress();
//    }

//    @Override
//    public Socket accept() throws IOException
//    {
//        return super.accept();
//    }

//    @Override
//    public void close() throws IOException
//    {
//        super.close();
//    }

//    @Override
//    public ServerSocketChannel getChannel()
//    {
//        return super.getChannel();
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
//    public synchronized void setSoTimeout(int timeout) throws SocketException
//    {
//        super.setSoTimeout(timeout);
//    }

//    @Override
//    public synchronized int getSoTimeout() throws IOException
//    {
//        return super.getSoTimeout();
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
//    public String toString()
//    {
//        return super.toString();
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
//    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth)
//    {
//        super.setPerformancePreferences(connectionTime, latency, bandwidth);
//    }
}
