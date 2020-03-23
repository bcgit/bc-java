package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;

import javax.net.ssl.SSLServerSocketFactory;

class ProvSSLServerSocketFactory
    extends SSLServerSocketFactory
{
    protected final ContextData contextData;

    ProvSSLServerSocketFactory(ContextData contextData)
    {
        super();

        this.contextData = contextData;
    }

    @Override
    public ServerSocket createServerSocket() throws IOException
    {
        return new ProvSSLServerSocket(contextData);
    }

    @Override
    public ServerSocket createServerSocket(int port) throws IOException
    {
        return new ProvSSLServerSocket(contextData, port);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog) throws IOException
    {
        return new ProvSSLServerSocket(contextData, port, backlog);
    }

    @Override
    public ServerSocket createServerSocket(int port, int backlog, InetAddress ifAddress) throws IOException
    {
        return new ProvSSLServerSocket(contextData, port, backlog, ifAddress);
    }

    @Override
    public String[] getDefaultCipherSuites()
    {
        return contextData.getContext().getDefaultCipherSuites(false);
    }

    @Override
    public String[] getSupportedCipherSuites()
    {
        return contextData.getContext().getSupportedCipherSuites();
    }
}
