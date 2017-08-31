package org.bouncycastle.jsse.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.nio.channels.SocketChannel;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.bouncycastle.jsse.BCSSLConnection;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsProtocol;
import org.bouncycastle.tls.TlsServerProtocol;

class ProvSSLSocketWrap
    extends ProvSSLSocketBase
    implements ProvTlsManager
{
    protected final AppDataInput appDataIn = new AppDataInput();
    protected final AppDataOutput appDataOut = new AppDataOutput();

    protected final ProvSSLContextSpi context;
    protected final ContextData contextData;

    protected final Socket wrapSocket;
    protected final String wrapHost;
    protected final int wrapPort;
    protected final boolean wrapAutoClose;

    protected ProvSSLParameters sslParameters;
    protected boolean enableSessionCreation = true;
    protected boolean useClientMode = true;

    protected boolean initialHandshakeBegun = false;
    protected TlsProtocol protocol = null;
    protected ProvTlsPeer protocolPeer = null;
    protected BCSSLConnection connection = null;
    protected SSLSession handshakeSession = null;

    protected ProvSSLSocketWrap(ProvSSLContextSpi context, ContextData contextData, Socket s, String host, int port, boolean autoClose)
    {
        super();

        this.context = context;
        this.contextData = contextData;
        this.wrapSocket = s;
        this.wrapHost = host;
        this.wrapPort = port;
        this.wrapAutoClose = autoClose;
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
    public void bind(SocketAddress bindpoint) throws IOException
    {
        throw new SocketException("Wrapped socket should already be bound");
    }

    @Override
    public synchronized void close() throws IOException
    {
        if (protocol != null)
        {
            protocol.close();
        }
        if (wrapAutoClose)
        {
            wrapSocket.close();
        }
    }

    @Override
    public void connect(SocketAddress endpoint, int timeout) throws IOException
    {
        throw new SocketException("Wrapped socket should already be connected");
    }

    @Override
    public SocketChannel getChannel()
    {
        return wrapSocket.getChannel();
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
    public InetAddress getInetAddress()
    {
        return wrapSocket.getInetAddress();
    }

    @Override
    public InputStream getInputStream() throws IOException
    {
        return appDataIn;
    }

    @Override
    public boolean getKeepAlive() throws SocketException
    {
        return wrapSocket.getKeepAlive();
    }

    @Override
    public InetAddress getLocalAddress()
    {
        return wrapSocket.getLocalAddress();
    }

    @Override
    public int getLocalPort()
    {
        return wrapSocket.getLocalPort();
    }

    @Override
    public SocketAddress getLocalSocketAddress()
    {
        return wrapSocket.getLocalSocketAddress();
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
    public int getPort()
    {
        return wrapSocket.getPort();
    }

    @Override
    public int getReceiveBufferSize() throws SocketException
    {
        return wrapSocket.getReceiveBufferSize();
    }

    @Override
    public SocketAddress getRemoteSocketAddress()
    {
        return wrapSocket.getRemoteSocketAddress();
    }

    @Override
    public boolean getReuseAddress() throws SocketException
    {
        return wrapSocket.getReuseAddress();
    }

    @Override
    public int getSendBufferSize() throws SocketException
    {
        return wrapSocket.getSendBufferSize();
    }

    @Override
    public synchronized SSLSession getSession()
    {
        BCSSLConnection connection = getConnection();

        return connection == null ? ProvSSLSessionImpl.NULL_SESSION.getExportSession() : connection.getSession();
    }

    @Override
    public int getSoLinger() throws SocketException
    {
        return wrapSocket.getSoLinger();
    }

    @Override
    public int getSoTimeout() throws SocketException
    {
        return wrapSocket.getSoTimeout();
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
    public boolean getTcpNoDelay() throws SocketException
    {
        return wrapSocket.getTcpNoDelay();
    }

    @Override
    public int getTrafficClass() throws SocketException
    {
        return wrapSocket.getTrafficClass();
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
    public boolean isBound()
    {
        return wrapSocket.isBound();
    }

    @Override
    public boolean isConnected()
    {
        return wrapSocket.isConnected();
    }

    @Override
    public synchronized boolean isClosed()
    {
        return protocol != null && protocol.isClosed();
    }

    @Override
    public boolean isInputShutdown()
    {
        return wrapSocket.isInputShutdown();
    }

    @Override
    public boolean isOutputShutdown()
    {
        return wrapSocket.isOutputShutdown();
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
    public void setKeepAlive(boolean on) throws SocketException
    {
        wrapSocket.setKeepAlive(on);
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need)
    {
        sslParameters.setNeedClientAuth(need);
    }

    @Override
    public void setPerformancePreferences(int connectionTime, int latency, int bandwidth)
    {
        wrapSocket.setPerformancePreferences(connectionTime, latency, bandwidth);
    }

    @Override
    public void setReceiveBufferSize(int size) throws SocketException
    {
        wrapSocket.setReceiveBufferSize(size);
    }

    @Override
    public void setReuseAddress(boolean on) throws SocketException
    {
        wrapSocket.setReuseAddress(on);
    }

    @Override
    public void setSendBufferSize(int size) throws SocketException
    {
        wrapSocket.setSendBufferSize(size);
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters sslParameters)
    {
        this.sslParameters = SSLParametersUtil.toProvSSLParameters(sslParameters);
    }

    @Override
    public void setSoLinger(boolean on, int linger) throws SocketException
    {
        wrapSocket.setSoLinger(on, linger);
    }

    @Override
    public void setSoTimeout(int timeout) throws SocketException
    {
        wrapSocket.setSoTimeout(timeout);
    }

    @Override
    public void setTcpNoDelay(boolean on) throws SocketException
    {
        wrapSocket.setTcpNoDelay(on);
    }

    @Override
    public void setTrafficClass(int tc) throws SocketException
    {
        wrapSocket.setTrafficClass(tc);
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
                TlsClientProtocol clientProtocol = new TlsClientProtocol(wrapSocket.getInputStream(), wrapSocket.getOutputStream());
                this.protocol = clientProtocol;

                ProvTlsClient client = new ProvTlsClient(this);
                this.protocolPeer = client;
    
                clientProtocol.connect(client);
            }
            else
            {
                TlsServerProtocol serverProtocol = new TlsServerProtocol(wrapSocket.getInputStream(), wrapSocket.getOutputStream());
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

    @Override
    public String toString()
    {
        // TODO[jsse] Proper toString for sockets
        return wrapSocket.toString();
    }

    public String getPeerHost()
    {
        return wrapHost;
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
            synchronized (ProvSSLSocketWrap.this)
            {
                return protocol == null
                    ?   0
                    :   protocol.applicationDataAvailable();
            }
        }

        @Override
        public void close() throws IOException
        {
            ProvSSLSocketWrap.this.close();
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
            ProvSSLSocketWrap.this.close();
        }

        @Override
        public void flush() throws IOException
        {
            synchronized (ProvSSLSocketWrap.this)
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
