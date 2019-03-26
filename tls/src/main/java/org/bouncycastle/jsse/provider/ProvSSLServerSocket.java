package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

class ProvSSLServerSocket
    extends SSLServerSocket
{
    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;
    protected final ProvSSLParameters sslParameters;

    protected boolean enableSessionCreation = true;
    protected boolean useClientMode = false;

    protected ProvSSLServerSocket(ProvSSLContextSpi context, ContextData contextData)
        throws IOException
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.getDefaultParameters(!useClientMode);
    }

    protected ProvSSLServerSocket(ProvSSLContextSpi context, ContextData contextData, int port)
        throws IOException
    {
        super(port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.getDefaultParameters(!useClientMode);
    }

    protected ProvSSLServerSocket(ProvSSLContextSpi context, ContextData contextData, int port, int backlog)
        throws IOException
    {
        super(port, backlog);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.getDefaultParameters(!useClientMode);
    }

    protected ProvSSLServerSocket(ProvSSLContextSpi context, ContextData contextData, int port, int backlog, InetAddress address)
        throws IOException
    {
        super(port, backlog, address);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.getDefaultParameters(!useClientMode);
    }

    @Override
    public synchronized Socket accept() throws IOException
    {
        ProvSSLSocketDirect socket = SSLSocketUtil.create(context, contextData, enableSessionCreation,
            useClientMode, sslParameters.copy());

        implAccept(socket);
        socket.notifyConnected();

        return socket;
    }

    @Override
    public ServerSocketChannel getChannel()
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public synchronized boolean getEnableSessionCreation()
    {
        return enableSessionCreation;
    }

    @Override
    public synchronized String[] getEnabledCipherSuites()
    {
        return sslParameters.getCipherSuites();
    }

    @Override
    public synchronized String[] getEnabledProtocols()
    {
        return sslParameters.getProtocols();
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public synchronized SSLParameters getSSLParameters()
    {
        return SSLParametersUtil.getSSLParameters(sslParameters);
    }

    @Override
    public synchronized String[] getSupportedCipherSuites()
    {
        return context.getSupportedCipherSuites();
    }

    @Override
    public synchronized String[] getSupportedProtocols()
    {
        return context.getSupportedProtocols();
    }

    @Override
    public synchronized boolean getUseClientMode()
    {
        return useClientMode;
    }

    @Override
    public synchronized boolean getWantClientAuth()
    {
        return sslParameters.getWantClientAuth();
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean flag)
    {
        this.enableSessionCreation = flag;
    }

    @Override
    public synchronized void setEnabledCipherSuites(String[] suites)
    {
        sslParameters.setCipherSuites(suites);
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols)
    {
        sslParameters.setProtocols(protocols);
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need)
    {
        sslParameters.setNeedClientAuth(need);
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters sslParameters)
    {
        SSLParametersUtil.setSSLParameters(this.sslParameters, sslParameters);
    }

    @Override
    public synchronized void setUseClientMode(boolean useClientMode)
    {
        if (this.useClientMode != useClientMode)
        {
            context.updateDefaultProtocols(sslParameters, !useClientMode);

            this.useClientMode = useClientMode;
        }
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }
}
