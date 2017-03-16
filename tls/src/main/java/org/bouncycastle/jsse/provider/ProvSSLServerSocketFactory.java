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
        return new ProvSSLServerSocket(context, context.createContextData());
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        return new ProvSSLServerSocket(context, context.createContextData(), port);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException
    {
        return new ProvSSLServerSocket(context, context.createContextData(), port, backlog);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException
    {
        return new ProvSSLServerSocket(context, context.createContextData(), port, backlog, ifAddress);
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        return context.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return context.getSupportedCipherSuites();
    }
}
