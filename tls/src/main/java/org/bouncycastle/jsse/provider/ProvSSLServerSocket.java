package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.channels.ServerSocketChannel;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

class ProvSSLServerSocket
    extends SSLServerSocket
{

    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;

    protected ProvSSLParameters sslParameters;
    protected boolean enableSessionCreation = true;
    protected boolean useClientMode = false;

    protected ProvSSLServerSocket(ProvSSLContextSpi context, ContextData contextData)
        throws IOException
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLServerSocket(ProvSSLContextSpi context, ContextData contextData, int port)
        throws IOException
    {
        super(port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLServerSocket(ProvSSLContextSpi context, ContextData contextData, int port, int backlog)
        throws IOException
    {
        super(port, backlog);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLServerSocket(ProvSSLContextSpi context, ContextData contextData, int port, int backlog, InetAddress address)
        throws IOException
    {
        super(port, backlog, address);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    @Override
    public synchronized Socket accept() throws IOException
    {
//        SSLEngine engine = context.engineCreateSSLEngine(getInetAddress().getHostName(), getLocalPort());
//        SSLSocket socket = new ProvSSLSocket(engine);
        SSLSocket socket = new ProvSSLSocketDirect(context, contextData);

        implAccept(socket);

        if (ProvSSLParameters.hasSslParameters)
        {
            socket.setSSLParameters(SSLParametersUtil.toSSLParameters(sslParameters));
        }
        else
        {
            String[] cipherSuites = sslParameters.getCipherSuites();
            if (cipherSuites != null)
            {
                socket.setEnabledCipherSuites(cipherSuites);
            }
            String[] protocols = sslParameters.getProtocols();
            if (protocols != null)
            {
                socket.setEnabledProtocols(protocols);
            }

            if (sslParameters.getNeedClientAuth())
            {
                socket.setNeedClientAuth(true);
            }
            else if (sslParameters.getWantClientAuth())
            {
                socket.setWantClientAuth(true);
            }
            else
            {
                socket.setWantClientAuth(false);
            }
        }

        socket.setEnableSessionCreation(enableSessionCreation);
        socket.setUseClientMode(useClientMode);

        return socket;
    }

    @Override
    public ServerSocketChannel getChannel()
    {
//        return super.getChannel();
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
        return SSLParametersUtil.toSSLParameters(sslParameters);
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
        if (!context.isSupportedCipherSuites(suites))
        {
            throw new IllegalArgumentException("'suites' cannot be null, or contain unsupported cipher suites");
        }

        sslParameters.setCipherSuites(suites);
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols)
    {
        if (!context.isSupportedProtocols(protocols))
        {
            throw new IllegalArgumentException("'protocols' cannot be null, or contain unsupported protocols");
        }

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
        this.sslParameters = SSLParametersUtil.toProvSSLParameters(sslParameters);
    }

    @Override
    public synchronized void setUseClientMode(boolean mode)
    {
        this.useClientMode = mode;
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }
}
