package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

class ProvSSLSocketDirect
    extends ProvSSLSocketBase
    implements ProvTlsManager
{
    protected final AppDataInput appDataIn = new AppDataInput();
    protected final AppDataOutput appDataOut = new AppDataOutput();

    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;

    protected ProvSSLParameters sslParameters;
    protected boolean enableSessionCreation = true;
    protected boolean useClientMode = true;

    protected boolean initialHandshakeBegun = false;
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected BCSSLConnection connection = null;
    protected SSLSession handshakeSession = null;

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData)
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port, InetAddress clientAddress, int clientPort)
        throws IOException
    {
        super(address, port, clientAddress, clientPort);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData, InetAddress address, int port) throws IOException
    {
        super(address, port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData, String host, int port, InetAddress clientAddress, int clientPort)
        throws IOException, UnknownHostException
    {
        super(host, port, clientAddress, clientPort);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
    }

    protected ProvSSLSocketDirect(ProvSSLContextSpi context, ContextData contextData, String host, int port) throws IOException, UnknownHostException
    {
        super(host, port);

        this.context = context;
        this.contextData = contextData;
        this.sslParameters = ProvSSLParameters.extractDefaultParameters(context);
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

    public synchronized BCSSLConnection getConnection()
    {
        try
        {
            handshakeIfNecessary();
        }
        catch (Exception e)
        {
            // TODO[jsse] Logging?
        }

        return connection;
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
    public InputStream getInputStream() throws IOException
    {
        return appDataIn;
    }

    @Override
    public synchronized boolean getNeedClientAuth()
    {
        return sslParameters.getNeedClientAuth();
    }

    @Override
    public OutputStream getOutputStream() throws IOException
    {
        return appDataOut;
    }

    @Override
    public synchronized SSLSession getSession()
    {
        BCSSLConnection connection = getConnection();

        return connection == null ? ProvSSLSessionImpl.NULL_SESSION.getExportSession() : connection.getSession();
    }

    @Override
    public synchronized SSLParameters getSSLParameters()
    {
        return SSLParametersUtil.toSSLParameters(sslParameters);
    }

    public synchronized ProvSSLParameters getProvSSLParameters()
    {
        return sslParameters;
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
        this.sslParameters = SSLParametersUtil.toProvSSLParameters(sslParameters);
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
        }
        finally
        {
            this.handshakeSession = null;
        }
    }

    public String getPeerHost()
    {
        InetAddress peerAddress = getInetAddress();
        if (peerAddress != null)
        {
            String peerHost = peerAddress.toString();
            int pos = peerHost.lastIndexOf('/');
            if (pos > 0)
            {
                return peerHost.substring(0,  pos);
            }
        }
        return null;
    }

    public int getPeerPort()
    {
        return getPort();
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

    public synchronized void notifyHandshakeComplete(ProvSSLConnection connection)
    {
        this.connection = connection;
    }

    synchronized void handshakeIfNecessary() throws IOException
    {
        if (!initialHandshakeBegun)
        {
            startHandshake();
        }
    }

    class AppDataInput extends InputStream
    {
        @Override
        public int available() throws IOException
        {
            synchronized (ProvSSLSocketDirect.this)
            {
                return protocol == null
                    ?   0
                    :   protocol.applicationDataAvailable();
            }
        }

        @Override
        public void close() throws IOException
        {
            ProvSSLSocketDirect.this.close();
        }

        @Override
        public int read() throws IOException
        {
            handshakeIfNecessary();

            byte[] buf = new byte[1];
            int ret = protocol.readApplicationData(buf, 0, 1);
            return ret < 0 ? -1 : buf[0] & 0xFF;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException
        {
            if (len < 1)
            {
                return 0;
            }

            handshakeIfNecessary();
            return protocol.readApplicationData(b, off, len);
        }
    }

    class AppDataOutput extends OutputStream
    {
        @Override
        public void close() throws IOException
        {
            ProvSSLSocketDirect.this.close();
        }

        @Override
        public void flush() throws IOException
        {
            synchronized (ProvSSLSocketDirect.this)
            {
                if (protocol != null)
                {
                    protocol.flush();
                }
            }
        }

        @Override
        public void write(int b) throws IOException
        {
            handshakeIfNecessary();

            byte[] buf = new byte[]{ (byte)b };
            protocol.writeApplicationData(buf, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException
        {
            if (len > 0)
            {
                handshakeIfNecessary();
                protocol.writeApplicationData(b, off, len);
            }
        }
    }
}
