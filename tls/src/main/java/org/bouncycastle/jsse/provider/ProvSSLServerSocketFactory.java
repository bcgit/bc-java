package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import javax.net.ssl.SSLServerSocketFactory;

class ProvSSLServerSocketFactory
    extends SSLServerSocketFactory
{
    protected final ProvSSLContextSpi context;

    ProvSSLServerSocketFactory(ProvSSLContextSpi context)
    {
        super();

        this.context = context;
    }

    @Override
    public ServerSocket createServerSocket() throws IOException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        return new ProvSSLServerSocket(port, context);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        throw new UnsupportedOperationException();
    }
}
