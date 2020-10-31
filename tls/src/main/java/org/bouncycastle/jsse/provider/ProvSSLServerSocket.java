package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;

class ProvSSLServerSocket
    extends SSLServerSocket
{
    protected final ContextData contextData;
    protected final ProvSSLParameters sslParameters;

    protected boolean enableSessionCreation = true;
    protected boolean useClientMode = false;

    protected ProvSSLServerSocket(ContextData contextData)
        throws IOException
    {
        super();

        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(useClientMode);
    }

    protected ProvSSLServerSocket(ContextData contextData, int port)
        throws IOException
    {
        super(port);

        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(useClientMode);
    }

    protected ProvSSLServerSocket(ContextData contextData, int port, int backlog)
        throws IOException
    {
        super(port, backlog);

        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(useClientMode);
    }

    protected ProvSSLServerSocket(ContextData contextData, int port, int backlog, InetAddress address)
        throws IOException
    {
        super(port, backlog, address);

        this.contextData = contextData;
        this.sslParameters = contextData.getContext().getDefaultSSLParameters(useClientMode);
    }

    @Override
    public synchronized Socket accept() throws IOException
    {
        ProvSSLSocketDirect socket = SSLSocketUtil.create(contextData, enableSessionCreation, useClientMode,
            sslParameters.copy());

        implAccept(socket);
        socket.notifyConnected();

        return socket;
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
        return contextData.getContext().getSupportedCipherSuites();
    }

    @Override
    public synchronized String[] getSupportedProtocols()
    {
        return contextData.getContext().getSupportedProtocols();
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
            contextData.getContext().updateDefaultSSLParameters(sslParameters, useClientMode);

            this.useClientMode = useClientMode;
        }
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }
}
