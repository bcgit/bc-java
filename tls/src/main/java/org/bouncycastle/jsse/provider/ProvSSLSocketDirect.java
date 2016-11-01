package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

class ProvSSLSocketDirect
    extends ProvSSLSocketBase
    implements ProvTlsManager
{
    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;

    protected SSLParameters sslParameters;
    protected boolean enableSessionCreation = false;
    protected boolean useClientMode = true;

    protected boolean initialHandshakeBegun = false;
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected ProvSSLSession session = ProvSSLSession.NULL_SESSION;
    protected ProvSSLSession handshakeSession = null;

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData)
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.engineGetDefaultSSLParameters();
    }

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port, InetAddress clientAddress, int clientPort)
        throws IOException
    {
        super(address, port, clientAddress, clientPort);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.engineGetDefaultSSLParameters();
    }

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port) throws IOException
    {
        super(address, port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.engineGetDefaultSSLParameters();
    }

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        super(host, port, clientAddress, clientPort);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.engineGetDefaultSSLParameters();
    }

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData, String host, int port) throws IOException, UnknownHostException
    {
        super(host, port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = context.engineGetDefaultSSLParameters();
    }

    public ProvSSLContextSpi getContext()
    {
        return context;
    }

    public ContextData getContextData()
    {
        return contextData;
    }

    @Override
    public synchronized void close() throws IOException
    {
        if (protocol != null)
        {
            protocol.close();
        }
        super.close();
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
    public synchronized boolean getEnableSessionCreation()
    {
        return enableSessionCreation;
    }

    @Override
    public synchronized SSLSession getHandshakeSession()
    {
        return handshakeSession;
    }

    @Override
    public synchronized InputStream getInputStream() throws IOException
    {
        if (!initialHandshakeBegun)
        {
//            return super.getInputStream();
            throw new UnsupportedOperationException();
        }
        if (protocol == null)
        {
            throw new SocketException();
        }
        return protocol.getInputStream();
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public synchronized OutputStream getOutputStream() throws IOException
    {
        if (!initialHandshakeBegun)
        {
//            return super.getOutputStream();
            throw new UnsupportedOperationException();
        }
        if (protocol == null)
        {
            throw new SocketException();
        }
        return protocol.getOutputStream();
    }

    @Override
    public synchronized SSLSession getSession()
    {
        /*
         * "This method will initiate the initial handshake if necessary and then block until the
         * handshake has been established."
         */
        if (!initialHandshakeBegun)
        {
            try
            {
                startHandshake();
            }
            catch (Exception e)
            {
                // TODO[jsse] Logging?
            }
        }

        return session;
    }

    @Override
    public synchronized SSLParameters getSSLParameters()
    {
        return context.copySSLParameters(sslParameters);
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
    public synchronized void setEnableSessionCreation(boolean flag)
    {
        this.enableSessionCreation = flag;
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need)
    {
        sslParameters.setNeedClientAuth(need);
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters sslParameters)
    {
        this.sslParameters = context.copySSLParameters(sslParameters);
    }

    @Override
    public synchronized void setUseClientMode(boolean mode)
    {
        if (initialHandshakeBegun && mode != this.useClientMode)
        {
            throw new IllegalArgumentException("Mode cannot be changed after the initial handshake has begun");
        }

        this.useClientMode = mode;
    }

    @Override
    public synchronized void setWantClientAuth(boolean want)
    {
        sslParameters.setWantClientAuth(want);
    }

    @Override
    public synchronized void startHandshake() throws IOException
    {
        if (initialHandshakeBegun)
        {
            throw new UnsupportedOperationException("Renegotiation not supported");
        }

        this.initialHandshakeBegun = true;

        try
        {
            // TODO[jsse] Check for session to re-use and apply to handshake
            // TODO[jsse] Allocate this.handshakeSession and update it during handshake
    
            if (this.useClientMode)
            {
                TlsClientProtocol clientProtocol = new TlsClientProtocol(super.getInputStream(), super.getOutputStream());
                this.protocol = clientProtocol;
    
                ProvTlsClient client = new ProvTlsClient(this);
                this.protocolPeer = client;
    
                clientProtocol.connect(client);
            }
            else
            {
                TlsServerProtocol serverProtocol = new TlsServerProtocol(super.getInputStream(), super.getOutputStream());
                this.protocol = serverProtocol;
    
                ProvTlsServer server = new ProvTlsServer(this);
                this.protocolPeer = server;
    
                serverProtocol.accept(server);
            }

            // TODO[jsse] this.session needs to be set after a successful handshake
        }
        finally
        {
            this.handshakeSession = null;
        }
    }

    public boolean isClientTrusted(X509Certificate[] chain, String authType)
    {
        // TODO[jsse] Consider X509ExtendedTrustManager and/or HostnameVerifier functionality

        X509TrustManager tm = contextData.getTrustManager();
        if (tm != null)
        {
            try
            {
                tm.checkClientTrusted(chain, authType);
                return true;
            }
            catch (CertificateException e)
            {
            }
        }
        return false;
    }

    public boolean isServerTrusted(X509Certificate[] chain, String authType)
    {
        // TODO[jsse] Consider X509ExtendedTrustManager and/or HostnameVerifier functionality

        X509TrustManager tm = contextData.getTrustManager();
        if (tm != null)
        {
            try
            {
                tm.checkServerTrusted(chain, authType);
                return true;
            }
            catch (CertificateException e)
            {
            }
        }
        return false;
    }
}
